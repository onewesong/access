package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/edgefn/auth-center/config"
	"github.com/edgefn/auth-center/provider"
	"github.com/edgefn/auth-center/store"
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
