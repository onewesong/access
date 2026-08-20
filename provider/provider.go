package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"net/http"
)

var ErrDenied = errors.New("provider denied access")

type User struct {
	Subject, Email, Name, Avatar string
	EmailVerified                bool
	Claims                       map[string]any
}
type IdentityProvider interface {
	Name() string
	AuthorizeURL(state, nonce, challenge string) string
	Exchange(context.Context, string) (*oauth2.Token, error)
	User(context.Context, *oauth2.Token) (User, error)
}
type OAuth struct {
	name    string
	cfg     oauth2.Config
	userURL string
}

func NewGitHub(id, secret, redirect string) IdentityProvider {
	return &OAuth{"github", oauth2.Config{ClientID: id, ClientSecret: secret, RedirectURL: redirect, Endpoint: github.Endpoint, Scopes: []string{"read:user", "user:email"}}, "https://api.github.com/user"}
}
func NewGoogle(id, secret, redirect string) IdentityProvider {
	return &OAuth{"google", oauth2.Config{ClientID: id, ClientSecret: secret, RedirectURL: redirect, Endpoint: google.Endpoint, Scopes: []string{"openid", "profile", "email"}}, "https://openidconnect.googleapis.com/v1/userinfo"}
}
func (o *OAuth) Name() string { return o.name }
func (o *OAuth) AuthorizeURL(s, n, c string) string {
	return o.cfg.AuthCodeURL(s, oauth2.AccessTypeOffline)
}
func (o *OAuth) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return o.cfg.Exchange(ctx, code)
}
func (o *OAuth) User(ctx context.Context, t *oauth2.Token) (User, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.userURL, nil)
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		return User{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return User{}, fmt.Errorf("provider status %d", resp.StatusCode)
	}
	var v map[string]any
	if e := json.NewDecoder(resp.Body).Decode(&v); e != nil {
		return User{}, e
	}
	u := User{Claims: v}
	if x, ok := v["sub"].(string); ok {
		u.Subject = x
	}
	if u.Subject == "" {
		if x, ok := v["id"].(float64); ok {
			u.Subject = fmt.Sprintf("%.0f", x)
		}
	}
	u.Email, _ = v["email"].(string)
	u.Name, _ = v["name"].(string)
	u.Avatar, _ = v["picture"].(string)
	u.EmailVerified, _ = v["email_verified"].(bool)
	return u, nil
}

type OIDC struct {
	OAuth
	verifier *oidc.IDTokenVerifier
}
