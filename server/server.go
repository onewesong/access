package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/edgefn/auth-center/config"
	"github.com/edgefn/auth-center/provider"
	"github.com/edgefn/auth-center/store"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type authCode struct {
	ClientID, RedirectURI, Provider, Subject, Nonce, Challenge string
	User                                                       provider.User
	Exp                                                        time.Time
}
type authState struct{ ClientID, RedirectURI, State, Nonce, Challenge string }
type token struct {
	Access   string
	User     provider.User
	ClientID string
	Exp      time.Time
}
type Server struct {
	cfg       config.Config
	st        store.Store
	providers map[string]provider.IdentityProvider
	clients   map[string]config.Client
	key       *rsa.PrivateKey
	mu        sync.Mutex
	codes     map[string]authCode
	tokens    map[string]token
}

func New(cfg config.Config, st store.Store, ps []provider.IdentityProvider) *Server {
	s := &Server{cfg: cfg, st: st, providers: map[string]provider.IdentityProvider{}, clients: map[string]config.Client{}, codes: map[string]authCode{}, tokens: map[string]token{}}
	for _, p := range ps {
		s.providers[p.Name()] = p
	}
	for _, c := range cfg.Clients {
		s.clients[c.ID] = c
	}
	s.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	return s
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/.well-known/openid-configuration", s.discovery)
	m.HandleFunc("/oauth/authorize", s.authorize)
	m.HandleFunc("/oauth/callback/", s.callback)
	m.HandleFunc("/oauth/token", s.token)
	m.HandleFunc("/userinfo", s.userinfo)
	m.HandleFunc("/oauth/introspect", s.introspect)
	m.HandleFunc("/oauth/jwks", s.jwks)
	m.HandleFunc("/oauth/logout", s.logout)
	m.HandleFunc("/healthz", s.health)
	m.HandleFunc("/readyz", s.ready)
	m.Handle("/metrics", promhttp.Handler())
	return security(m)
}
func security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	s.json(w, map[string]any{"issuer": s.cfg.Issuer, "authorization_endpoint": s.cfg.Issuer + "/oauth/authorize", "token_endpoint": s.cfg.Issuer + "/oauth/token", "userinfo_endpoint": s.cfg.Issuer + "/userinfo", "jwks_uri": s.cfg.Issuer + "/oauth/jwks", "introspection_endpoint": s.cfg.Issuer + "/oauth/introspect", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "scopes_supported": []string{"openid", "profile", "email"}})
}
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, ok := s.clients[q.Get("client_id")]
	if !ok || !contains(c.RedirectURIs, q.Get("redirect_uri")) {
		http.Error(w, "invalid client or redirect_uri", 400)
		return
	}
	if q.Get("response_type") != "code" {
		http.Error(w, "response_type must be code", 400)
		return
	}
	p := q.Get("provider")
	if p == "" {
		p = firstProvider(s.providers)
	}
	pr, ok := s.providers[p]
	if !ok {
		http.Error(w, "unknown provider", 400)
		return
	}
	state := q.Get("state")
	nonce := q.Get("nonce")
	challenge := q.Get("code_challenge")
	if c.RequirePKCE && challenge == "" {
		http.Error(w, "PKCE required", 400)
		return
	}
	cb := s.cfg.Issuer + "/oauth/callback/" + url.PathEscape(p)
	b, _ := json.Marshal(authState{ClientID: c.ID, RedirectURI: q.Get("redirect_uri"), State: state, Nonce: nonce, Challenge: challenge})
	encoded := base64.RawURLEncoding.EncodeToString(b)
	http.Redirect(w, r, pr.AuthorizeURL(encoded, nonce, challenge)+"&redirect_uri="+url.QueryEscape(cb), 302)
}
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/oauth/callback/")
	pr, ok := s.providers[p]
	if !ok {
		http.Error(w, "unknown provider", 400)
		return
	}
	var as authState
	if b, e := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("state")); e != nil || json.Unmarshal(b, &as) != nil {
		http.Error(w, "invalid state", 400)
		return
	}
	t, e := pr.Exchange(r.Context(), r.URL.Query().Get("code"))
	if e != nil {
		http.Error(w, "provider exchange failed", 502)
		return
	}
	u, e := pr.User(r.Context(), t)
	if e != nil {
		http.Error(w, "provider user failed", 502)
		return
	}
	u.Claims["provider"] = p
	id := random()
	s.mu.Lock()
	s.codes[id] = authCode{ClientID: as.ClientID, RedirectURI: as.RedirectURI, Provider: p, Subject: u.Subject, User: u, Nonce: as.Nonce, Challenge: as.Challenge, Exp: time.Now().Add(s.cfg.CodeTTL)}
	s.mu.Unlock()
	target, _ := url.Parse(as.RedirectURI)
	q := target.Query()
	q.Set("code", id)
	q.Set("state", as.State)
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), 302)
}
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.Form.Get("grant_type") != "authorization_code" {
		http.Error(w, "unsupported grant", 400)
		return
	}
	code := r.Form.Get("code")
	s.mu.Lock()
	ac, ok := s.codes[code]
	delete(s.codes, code)
	s.mu.Unlock()
	if !ok || time.Now().After(ac.Exp) {
		http.Error(w, "invalid code", 400)
		return
	}
	if ac.Challenge != "" {
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != ac.Challenge {
			http.Error(w, "invalid verifier", 400)
			return
		}
	}
	at := random()
	s.mu.Lock()
	s.tokens[at] = token{Access: at, User: ac.User, ClientID: ac.ClientID, Exp: time.Now().Add(s.cfg.AccessTokenTTL)}
	s.mu.Unlock()
	s.json(w, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(s.cfg.AccessTokenTTL.Seconds()), "id_token": at, "scope": "openid profile email"})
}
func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	t := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	x, ok := s.tokens[t]
	s.mu.Unlock()
	if !ok || time.Now().After(x.Exp) {
		http.Error(w, "invalid token", 401)
		return
	}
	s.json(w, map[string]any{"sub": x.User.Subject, "email": x.User.Email, "email_verified": x.User.EmailVerified, "name": x.User.Name, "picture": x.User.Avatar})
}
func (s *Server) introspect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	t := r.Form.Get("token")
	s.mu.Lock()
	x, ok := s.tokens[t]
	s.mu.Unlock()
	s.json(w, map[string]any{"active": ok && time.Now().Before(x.Exp), "sub": x.User.Subject, "client_id": x.ClientID, "exp": x.Exp.Unix()})
}
func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(s.key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.key.PublicKey.E)).Bytes())
	s.json(w, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "auth-center", "n": n, "e": e}}})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("post_logout_redirect_uri"), 302)
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	s.json(w, map[string]string{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if e := s.st.Ping(r.Context()); e != nil {
		http.Error(w, "not ready", 503)
		return
	}
	s.json(w, map[string]string{"status": "ready"})
}
func (s *Server) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func random() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func sign(v string) string { return v }
func firstProvider(m map[string]provider.IdentityProvider) string {
	for k := range m {
		return k
	}
	return ""
}
func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

var _ = context.Background
var _ = fmt.Sprint
