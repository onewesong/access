package server

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/edgefn/auth-center/config"
	"github.com/edgefn/auth-center/identity"
	"github.com/edgefn/auth-center/policy"
	"github.com/edgefn/auth-center/provider"
	"github.com/edgefn/auth-center/store"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type authCode struct {
	ClientID, RedirectURI, Provider, Subject, UserID, Nonce, Challenge string
	User                                                               provider.User
	Exp                                                                time.Time
}
type authState struct{ ClientID, RedirectURI, State, Nonce, Challenge string }
type token struct {
	Access   string
	User     provider.User
	UserID   string
	ClientID string
	Exp      time.Time
	IssuedAt time.Time
}
type refreshToken struct {
	Token, ClientID, Access, FamilyID string
	User                              provider.User
	UserID                            string
	Exp                               time.Time
	Used                              bool
}
type Server struct {
	cfg       config.Config
	st        store.Store
	ident     identity.Service
	providers map[string]provider.IdentityProvider
	clients   map[string]config.Client
	key       *rsa.PrivateKey
	keys      map[string]*rsa.PrivateKey
	activeKID string
	logger    *slog.Logger
}

func New(cfg config.Config, st store.Store, ps []provider.IdentityProvider) *Server {
	s := &Server{cfg: cfg, st: st, ident: identity.Service{Store: st}, providers: map[string]provider.IdentityProvider{}, clients: map[string]config.Client{}, logger: slog.Default()}
	for _, p := range ps {
		s.providers[p.Name()] = p
	}
	for _, c := range cfg.Clients {
		s.clients[c.ID] = c
	}
	s.keys, s.activeKID, s.key = loadSigningKeys(cfg)
	return s
}
func loadSigningKey(raw string) *rsa.PrivateKey {
	if raw != "" {
		if b, e := base64.StdEncoding.DecodeString(raw); e == nil {
			if k, e := x509.ParsePKCS1PrivateKey(b); e == nil {
				return k
			}
		}
	}
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		panic(e)
	}
	return k
}
func loadSigningKeys(cfg config.Config) (map[string]*rsa.PrivateKey, string, *rsa.PrivateKey) {
	raws := append([]string{}, cfg.SigningKeys...)
	if cfg.SigningKey != "" {
		raws = append(raws, cfg.SigningKey)
	}
	keys := map[string]*rsa.PrivateKey{}
	active := ""
	for _, raw := range raws {
		if k := parseSigningKey(raw); k != nil {
			kid := keyID(k)
			keys[kid] = k
			if active == "" {
				active = kid
			}
		}
	}
	if len(keys) == 0 {
		k := loadSigningKey("")
		active = keyID(k)
		keys[active] = k
	}
	return keys, active, keys[active]
}
func parseSigningKey(raw string) *rsa.PrivateKey {
	b, e := base64.StdEncoding.DecodeString(raw)
	if e != nil {
		return nil
	}
	k, e := x509.ParsePKCS1PrivateKey(b)
	if e != nil {
		return nil
	}
	return k
}
func keyID(k *rsa.PrivateKey) string {
	sum := sha256.Sum256(k.PublicKey.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:6])
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/.well-known/openid-configuration", s.discovery)
	m.HandleFunc("/oauth/authorize", s.authorize)
	m.HandleFunc("/oauth/callback/", s.callback)
	m.HandleFunc("/oauth/token", s.token)
	m.HandleFunc("/oauth/revoke", s.revoke)
	m.HandleFunc("/oauth/session/revoke-all", s.revokeAll)
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
	s.json(w, map[string]any{"issuer": s.cfg.Issuer, "authorization_endpoint": s.cfg.Issuer + "/oauth/authorize", "token_endpoint": s.cfg.Issuer + "/oauth/token", "userinfo_endpoint": s.cfg.Issuer + "/userinfo", "jwks_uri": s.cfg.Issuer + "/oauth/jwks", "introspection_endpoint": s.cfg.Issuer + "/oauth/introspect", "revocation_endpoint": s.cfg.Issuer + "/oauth/revoke", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "scopes_supported": []string{"openid", "profile", "email"}})
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
	encoded := s.signState(base64.RawURLEncoding.EncodeToString(b))
	target, _ := url.Parse(pr.AuthorizeURL(encoded, nonce, challenge))
	query := target.Query()
	query.Set("redirect_uri", cb)
	if nonce != "" {
		query.Set("nonce", nonce)
	}
	if challenge != "" {
		query.Set("code_challenge", challenge)
		query.Set("code_challenge_method", "S256")
	}
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), 302)
}
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/oauth/callback/")
	pr, ok := s.providers[p]
	if !ok {
		http.Error(w, "unknown provider", 400)
		return
	}
	var as authState
	stateValue, valid := s.verifyState(r.URL.Query().Get("state"))
	if b, e := base64.RawURLEncoding.DecodeString(stateValue); !valid || e != nil || json.Unmarshal(b, &as) != nil {
		http.Error(w, "invalid state", 400)
		return
	}
	t, e := pr.Exchange(r.Context(), r.URL.Query().Get("code"))
	if e != nil {
		http.Error(w, "provider exchange failed", 502)
		return
	}
	u, e := pr.User(r.Context(), t, as.Nonce)
	if e != nil {
		http.Error(w, "provider user failed", 502)
		return
	}
	if u.Subject == "" || (p == "google" && !u.EmailVerified) {
		http.Error(w, "provider identity is not verified", http.StatusForbidden)
		return
	}
	u.Claims["provider"] = p
	usr, e := s.ident.Resolve(r.Context(), p, u)
	if e != nil {
		http.Error(w, "unable to persist identity", http.StatusServiceUnavailable)
		return
	}
	if polName := s.clients[as.ClientID].Policy; polName != "" {
		pol := s.cfg.Policies[polName]
		if (pol.GitHubOrganization != "" || pol.GitHubTeam != "") && p == "github" {
			login, _ := u.Claims["login"].(string)
			checker, ok := pr.(provider.MembershipChecker)
			if !ok || login == "" {
				http.Error(w, "github membership unavailable", 503)
				return
			}
			allowed, err := checker.CheckMembership(r.Context(), t, pol.GitHubOrganization, pol.GitHubTeam, login)
			if err != nil {
				http.Error(w, "github membership check failed", 503)
				return
			}
			if !allowed {
				http.Error(w, "access denied by github membership", 403)
				return
			}
		}
		if !policy.Allow(pol, u) {
			s.logger.Info("audit", "event", "login_denied", "provider", p, "client_id", as.ClientID, "reason", "policy")
			http.Error(w, "access denied by policy", http.StatusForbidden)
			return
		}
	}
	s.logger.Info("audit", "event", "login_succeeded", "provider", p, "client_id", as.ClientID, "user_id", usr.ID)
	id := random()
	if e := s.st.Set(r.Context(), "code:"+id, authCode{ClientID: as.ClientID, RedirectURI: as.RedirectURI, Provider: p, Subject: u.Subject, UserID: usr.ID, User: u, Nonce: as.Nonce, Challenge: as.Challenge, Exp: time.Now().Add(s.cfg.CodeTTL)}, s.cfg.CodeTTL); e != nil {
		http.Error(w, "unable to save authorization code", 503)
		return
	}
	target, _ := url.Parse(as.RedirectURI)
	q := target.Query()
	q.Set("code", id)
	q.Set("state", as.State)
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), 302)
}
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	clientID, clientSecret, ok := s.clientCredentials(r)
	if !ok {
		http.Error(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	if r.Form.Get("grant_type") == "refresh_token" {
		s.refresh(w, r, clientID)
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		http.Error(w, "unsupported grant", 400)
		return
	}
	code := r.Form.Get("code")
	var ac authCode
	if e := s.st.Consume(r.Context(), "code:"+code, &ac); e != nil || time.Now().After(ac.Exp) {
		http.Error(w, "invalid code", 400)
		return
	}
	c, ok := s.clients[clientID]
	if !ok || c.ID != ac.ClientID || !contains(c.RedirectURIs, r.Form.Get("redirect_uri")) || (c.Secret != "" && c.Secret != clientSecret) {
		http.Error(w, "invalid client", 400)
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
	rt := random()
	exp := time.Now().Add(s.cfg.AccessTokenTTL)
	if e := s.st.Set(r.Context(), "token:"+at, token{Access: at, UserID: ac.UserID, User: ac.User, ClientID: ac.ClientID, Exp: exp, IssuedAt: time.Now().UTC()}, s.cfg.AccessTokenTTL); e != nil {
		http.Error(w, "unable to save token", 503)
		return
	}
	family := random()
	if e := s.st.Set(r.Context(), "refresh-family:"+family, true, 30*24*time.Hour); e != nil {
		http.Error(w, "unable to save refresh family", 503)
		return
	}
	if e := s.st.Set(r.Context(), "refresh:"+rt, refreshToken{Token: rt, ClientID: ac.ClientID, Access: at, FamilyID: family, UserID: ac.UserID, User: ac.User, Exp: time.Now().Add(30 * 24 * time.Hour)}, 30*24*time.Hour); e != nil {
		http.Error(w, "unable to save refresh token", 503)
		return
	}
	idToken, e := s.idToken(ac, exp)
	if e != nil {
		http.Error(w, "unable to sign token", 503)
		return
	}
	s.json(w, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(s.cfg.AccessTokenTTL.Seconds()), "refresh_token": rt, "id_token": idToken, "scope": "openid profile email"})
}
func (s *Server) refresh(w http.ResponseWriter, r *http.Request, clientID string) {
	var old refreshToken
	rt := r.Form.Get("refresh_token")
	if e := s.st.Consume(r.Context(), "refresh:"+rt, &old); e != nil {
		var used string
		if s.st.Get(r.Context(), "refresh-used:"+rt, &used) == nil {
			if used != "" {
				_ = s.st.Delete(r.Context(), "refresh-family:"+used)
			}
		}
		http.Error(w, "invalid_grant", 400)
		return
	}
	if old.ClientID != clientID || time.Now().After(old.Exp) {
		_ = s.st.Delete(r.Context(), "refresh-family:"+old.FamilyID)
		http.Error(w, "invalid_grant", 400)
		return
	}
	var active bool
	if e := s.st.Get(r.Context(), "refresh-family:"+old.FamilyID, &active); e != nil || !active {
		http.Error(w, "invalid_grant", 400)
		return
	}
	_ = s.st.Set(r.Context(), "refresh-used:"+rt, old.FamilyID, 30*24*time.Hour)
	at := random()
	newRT := random()
	exp := time.Now().Add(s.cfg.AccessTokenTTL)
	if e := s.st.Set(r.Context(), "token:"+at, token{Access: at, UserID: old.UserID, User: old.User, ClientID: clientID, Exp: exp, IssuedAt: time.Now().UTC()}, s.cfg.AccessTokenTTL); e != nil {
		http.Error(w, "temporarily unavailable", 503)
		return
	}
	if e := s.st.Set(r.Context(), "refresh:"+newRT, refreshToken{Token: newRT, ClientID: clientID, Access: at, FamilyID: old.FamilyID, UserID: old.UserID, User: old.User, Exp: old.Exp}, time.Until(old.Exp)); e != nil {
		http.Error(w, "temporarily unavailable", 503)
		return
	}
	id, e := s.idToken(authCode{ClientID: clientID, UserID: old.UserID, User: old.User}, exp)
	if e != nil {
		http.Error(w, "temporarily unavailable", 503)
		return
	}
	s.json(w, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(s.cfg.AccessTokenTTL.Seconds()), "refresh_token": newRT, "id_token": id, "scope": "openid profile email"})
}
func (s *Server) clientCredentials(r *http.Request) (string, string, bool) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	c, exists := s.clients[id]
	return id, secret, exists && (c.Secret == "" || secret == c.Secret)
}
func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	t := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var x token
	if e := s.st.Get(r.Context(), "token:"+t, &x); e != nil || time.Now().After(x.Exp) {
		http.Error(w, "invalid token", 401)
		return
	}
	var u identity.User
	if e := s.st.Get(r.Context(), "user:"+x.UserID, &u); e == nil && (u.Disabled || (!u.RevokedBefore.IsZero() && !x.IssuedAt.IsZero() && !x.IssuedAt.After(u.RevokedBefore))) {
		http.Error(w, "user disabled", http.StatusForbidden)
		return
	}
	s.json(w, map[string]any{"sub": x.UserID, "provider_sub": x.User.Subject, "email": x.User.Email, "email_verified": x.User.EmailVerified, "name": x.User.Name, "picture": x.User.Avatar})
}
func (s *Server) introspect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	t := r.Form.Get("token")
	var x token
	e := s.st.Get(r.Context(), "token:"+t, &x)
	var u identity.User
	ue := s.st.Get(r.Context(), "user:"+x.UserID, &u)
	active := e == nil && ue == nil && !u.Disabled && (u.RevokedBefore.IsZero() || x.IssuedAt.IsZero() || x.IssuedAt.After(u.RevokedBefore)) && time.Now().Before(x.Exp)
	s.json(w, map[string]any{"active": active, "sub": x.User.Subject, "client_id": x.ClientID, "exp": x.Exp.Unix()})
}
func (s *Server) revokeAll(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if raw == "" {
		http.Error(w, "unauthorized", 401)
		return
	}
	var t token
	if e := s.st.Get(r.Context(), "token:"+raw, &t); e != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	var u identity.User
	if e := s.st.Get(r.Context(), "user:"+t.UserID, &u); e != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	u.RevokedBefore = time.Now().UTC()
	if e := s.st.Set(r.Context(), "user:"+u.ID, u, 0); e != nil {
		http.Error(w, "temporarily unavailable", 503)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	clientID, _, ok := s.clientCredentials(r)
	if !ok {
		http.Error(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	typ := r.Form.Get("token_type_hint")
	tok := r.Form.Get("token")
	if typ == "refresh_token" {
		var rt refreshToken
		if e := s.st.Get(r.Context(), "refresh:"+tok, &rt); e == nil && rt.ClientID == clientID {
			_ = s.st.Delete(r.Context(), "refresh:"+tok)
		}
	} else {
		var at token
		if e := s.st.Get(r.Context(), "token:"+tok, &at); e == nil && at.ClientID == clientID {
			_ = s.st.Delete(r.Context(), "token:"+tok)
		}
	}
	w.WriteHeader(http.StatusOK)
}
func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	keys := make([]any, 0, len(s.keys))
	for kid, k := range s.keys {
		n := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.PublicKey.E)).Bytes())
		keys = append(keys, map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e})
	}
	s.json(w, map[string]any{"keys": keys})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("post_logout_redirect_uri")
	if target == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	c, ok := s.clients[r.URL.Query().Get("client_id")]
	if !ok || !contains(c.RedirectURIs, target) {
		http.Error(w, "invalid post logout redirect", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
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
func (s *Server) signState(v string) string {
	mac := hmac.New(sha256.New, s.keyBytes())
	mac.Write([]byte(v))
	return v + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (s *Server) verifyState(v string) (string, bool) {
	p := strings.Split(v, ".")
	if len(p) != 2 {
		return "", false
	}
	sig, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil {
		return "", false
	}
	for _, k := range s.keys {
		mac := hmac.New(sha256.New, x509.MarshalPKCS1PrivateKey(k))
		mac.Write([]byte(p[0]))
		if hmac.Equal(sig, mac.Sum(nil)) {
			return p[0], true
		}
	}
	return "", false
}
func (s *Server) keyBytes() []byte { return x509.MarshalPKCS1PrivateKey(s.key) }
func (s *Server) idToken(ac authCode, exp time.Time) (string, error) {
	h := map[string]any{"alg": "RS256", "typ": "JWT", "kid": s.activeKID}
	sub := ac.UserID
	if sub == "" {
		sub = ac.User.Subject
	}
	p := map[string]any{"iss": s.cfg.Issuer, "sub": sub, "aud": ac.ClientID, "exp": exp.Unix(), "iat": time.Now().Unix(), "nonce": ac.Nonce, "email": ac.User.Email, "email_verified": ac.User.EmailVerified, "name": ac.User.Name}
	hb, _ := json.Marshal(h)
	pb, _ := json.Marshal(p)
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(input))
	sig, e := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if e != nil {
		return "", e
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
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
