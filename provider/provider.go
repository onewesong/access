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
	"net/url"
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
	User(context.Context, *oauth2.Token, string) (User, error)
}
type MembershipChecker interface {
	CheckMembership(context.Context, *oauth2.Token, string, string, string) (bool, error)
}
type OAuth struct {
	name    string
	cfg     oauth2.Config
	userURL string
}

func NewGitHub(id, secret, redirect string) IdentityProvider {
	return &OAuth{"github", oauth2.Config{ClientID: id, ClientSecret: secret, RedirectURL: redirect, Endpoint: github.Endpoint, Scopes: []string{"read:user", "user:email", "read:org"}}, "https://api.github.com/user"}
}
func NewGoogle(id, secret, redirect string) IdentityProvider {
	p, err := NewGoogleOIDC(context.Background(), id, secret, redirect)
	if err != nil {
		return &OAuth{"google", oauth2.Config{ClientID: id, ClientSecret: secret, RedirectURL: redirect, Endpoint: google.Endpoint, Scopes: []string{"openid", "profile", "email"}}, "https://openidconnect.googleapis.com/v1/userinfo"}
	}
	return p
}
func NewGoogleOIDC(ctx context.Context, id, secret, redirect string) (IdentityProvider, error) {
	op, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, err
	}
	return &OIDC{OAuth: OAuth{"google", oauth2.Config{ClientID: id, ClientSecret: secret, RedirectURL: redirect, Endpoint: google.Endpoint, Scopes: []string{"openid", "profile", "email"}}, "https://openidconnect.googleapis.com/v1/userinfo"}, verifier: op.Verifier(&oidc.Config{ClientID: id})}, nil
}
func (o *OAuth) Name() string { return o.name }
func (o *OAuth) AuthorizeURL(s, n, c string) string {
	return o.cfg.AuthCodeURL(s, oauth2.AccessTypeOffline)
}
func (o *OAuth) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return o.cfg.Exchange(ctx, code)
}
func (o *OAuth) User(ctx context.Context, t *oauth2.Token, _ string) (User, error) {
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
	if o.name == "github" {
		if email, verified := o.githubPrimaryEmail(ctx, t); email != "" {
			u.Email = email
			u.EmailVerified = verified
		}
	}
	return u, nil
}

func (o *OAuth) githubPrimaryEmail(ctx context.Context, t *oauth2.Token) (string, bool) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", false
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if json.NewDecoder(resp.Body).Decode(&emails) != nil {
		return "", false
	}
	for _, x := range emails {
		if x.Primary && x.Verified {
			return x.Email, true
		}
	}
	return "", false
}

func (o *OAuth) CheckMembership(ctx context.Context, t *oauth2.Token, organization, team, login string) (bool, error) {
	if o.name != "github" || organization == "" {
		return true, nil
	}
	ok, e := o.githubGet(ctx, t, "https://api.github.com/user/memberships/orgs/"+url.PathEscape(organization))
	if e != nil || !ok {
		return false, e
	}
	if team == "" {
		return true, nil
	}
	return o.githubGet(ctx, t, "https://api.github.com/orgs/"+url.PathEscape(organization)+"/teams/"+url.PathEscape(team)+"/memberships/"+url.PathEscape(login))
}
func (o *OAuth) githubGet(ctx context.Context, t *oauth2.Token, endpoint string) (bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		return false, e
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode/100 != 2 {
		return false, fmt.Errorf("github status %d", resp.StatusCode)
	}
	var v struct {
		State string `json:"state"`
	}
	if json.NewDecoder(resp.Body).Decode(&v) != nil {
		return false, fmt.Errorf("invalid github membership")
	}
	return v.State == "active" || v.State == "", nil
}

type OIDC struct {
	OAuth
	verifier *oidc.IDTokenVerifier
}
type oidcClaims struct {
	Subject       string      `json:"sub"`
	Email         string      `json:"email"`
	EmailVerified bool        `json:"email_verified"`
	Name          string      `json:"name"`
	Picture       string      `json:"picture"`
	Nonce         string      `json:"nonce"`
	Issuer        string      `json:"iss"`
	Audience      interface{} `json:"aud"`
}

func (o *OIDC) User(ctx context.Context, t *oauth2.Token, nonce string) (User, error) {
	raw, ok := t.Extra("id_token").(string)
	if !ok || raw == "" {
		return User{}, fmt.Errorf("OIDC provider did not return id_token")
	}
	idt, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return User{}, fmt.Errorf("verify OIDC id_token: %w", err)
	}
	var c oidcClaims
	if err = idt.Claims(&c); err != nil {
		return User{}, err
	}
	if nonce != "" && c.Nonce != nonce {
		return User{}, fmt.Errorf("OIDC nonce mismatch")
	}
	if c.Subject == "" || c.Email == "" || !c.EmailVerified {
		return User{}, ErrDenied
	}
	return User{Subject: c.Subject, Email: c.Email, EmailVerified: c.EmailVerified, Name: c.Name, Avatar: c.Picture, Claims: map[string]any{"sub": c.Subject, "email": c.Email, "email_verified": c.EmailVerified, "name": c.Name, "picture": c.Picture, "iss": c.Issuer}}, nil
}
