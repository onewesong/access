package server

import (
	"github.com/edgefn/auth-center/config"
	"github.com/edgefn/auth-center/provider"
	"github.com/edgefn/auth-center/store"
	"net/http/httptest"
	"net/url"
	"testing"
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
