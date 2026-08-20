package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/edgefn/auth-center/config"
	"github.com/edgefn/auth-center/identity"
	"github.com/edgefn/auth-center/provider"
	"github.com/edgefn/auth-center/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDiscovery(t *testing.T) {
	u, _ := url.Parse("http://localhost:8080")
	s := New(config.Config{Issuer: u.String(), Clients: []config.Client{{ID: "x"}}, Providers: []config.Provider{{Name: "github", Type: "github"}}}, store.NewMemory(), []provider.IdentityProvider{})
	r := httptest.NewRecorder()
	s.Handler().ServeHTTP(r, httptest.NewRequest("GET", "http://localhost:8080/.well-known/openid-configuration", nil))
	if r.Code != 200 {
		t.Fatal(r.Code)
	}
}

func TestTokenRefreshRotation(t *testing.T) {
	u, _ := url.Parse("http://localhost:8080")
	st := store.NewMemory()
	cfg := config.Config{Issuer: u.String(), AccessTokenTTL: time.Hour, CodeTTL: time.Minute, Clients: []config.Client{{ID: "c", Secret: "s", RedirectURIs: []string{"http://app/cb"}}}}
	s := New(cfg, st, nil)
	_ = st.Set(context.Background(), "code:x", authCode{ClientID: "c", RedirectURI: "http://app/cb", User: provider.User{Subject: "u", Email: "u@example.com"}, Exp: time.Now().Add(time.Minute)}, time.Minute)
	r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=authorization_code&code=x&client_id=c&client_secret=s&redirect_uri=http%3A%2F%2Fapp%2Fcb"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.token(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var first map[string]any
	_ = json.NewDecoder(w.Body).Decode(&first)
	rt := first["refresh_token"].(string)
	r2 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=refresh_token&refresh_token="+rt))
	r2.SetBasicAuth("c", "s")
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	s.token(w2, r2)
	if w2.Code != 200 {
		t.Fatal(w2.Code, w2.Body.String())
	}
	r3 := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=refresh_token&refresh_token="+rt))
	r3.SetBasicAuth("c", "s")
	r3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w3 := httptest.NewRecorder()
	s.token(w3, r3)
	if w3.Code == 200 {
		t.Fatal("refresh token was reusable")
	}
}

func TestJWKSKeyRing(t *testing.T) {
	a, _ := rsa.GenerateKey(rand.Reader, 1024)
	b, _ := rsa.GenerateKey(rand.Reader, 1024)
	cfg := config.Config{Issuer: "http://localhost", SigningKeys: []string{base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(a)), base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(b))}}
	s := New(cfg, store.NewMemory(), nil)
	w := httptest.NewRecorder()
	s.jwks(w, httptest.NewRequest("GET", "/oauth/jwks", nil))
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if json.NewDecoder(w.Body).Decode(&doc) != nil || len(doc.Keys) != 2 {
		t.Fatalf("expected two JWKS keys: %s", w.Body.String())
	}
}

func TestProxyVerify(t *testing.T) {
	st := store.NewMemory()
	s := New(config.Config{Issuer: "https://auth.example.com", Clients: []config.Client{{ID: "app", RedirectURIs: []string{"https://app.example.com/__auth/callback"}}}}, st, nil)
	ctx := context.Background()
	u := identity.User{ID: "u1", Email: "u@example.com"}
	_ = st.Set(ctx, "user:u1", u, 0)
	sid := "session"
	_ = st.Set(ctx, "proxy-session:"+sid, proxySession{ClientID: "app", UserID: "u1", User: provider.User{Subject: "p1", Email: "u@example.com", Claims: map[string]any{"provider": "github"}}, Exp: time.Now().Add(time.Hour), IssuedAt: time.Now()}, time.Hour)
	r := httptest.NewRequest("GET", "/oauth/proxy/verify", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-auth_center_session", Value: sid})
	r.Header.Set("X-Auth-Client-ID", "app")
	w := httptest.NewRecorder()
	s.proxyVerify(w, r)
	if w.Code != 200 || w.Header().Get("X-Auth-User") != "u1" {
		t.Fatalf("proxy verify status=%d headers=%v", w.Code, w.Header())
	}
}
