package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"strings"
	"time"
)

type Provider struct {
	Name         string   `yaml:"name"`
	Type         string   `yaml:"type"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Issuer       string   `yaml:"issuer"`
	Scopes       []string `yaml:"scopes"`
}
type Client struct {
	ID           string   `yaml:"id"`
	Secret       string   `yaml:"secret"`
	RedirectURIs []string `yaml:"redirect_uris"`
	Scopes       []string `yaml:"scopes"`
	RequirePKCE  bool     `yaml:"require_pkce"`
	Policy       string   `yaml:"policy"`
}
type Policy struct {
	AllowedProviders   []string `yaml:"allowed_providers"`
	EmailDomains       []string `yaml:"email_domains"`
	AllowedRoles       []string `yaml:"allowed_roles"`
	GitHubOrganization string   `yaml:"github_organization"`
	GitHubTeam         string   `yaml:"github_team"`
}
type Config struct {
	Issuer         string            `yaml:"issuer"`
	Addr           string            `yaml:"addr"`
	CookieSecure   bool              `yaml:"cookie_secure"`
	RedisAddr      string            `yaml:"redis_addr"`
	SigningKey     string            `yaml:"signing_key"`
	SigningKeys    []string          `yaml:"signing_keys"`
	EncryptionKey  string            `yaml:"encryption_key"`
	Providers      []Provider        `yaml:"providers"`
	Clients        []Client          `yaml:"clients"`
	Policies       map[string]Policy `yaml:"policies"`
	AccessTokenTTL time.Duration     `yaml:"-"`
	CodeTTL        time.Duration     `yaml:"-"`
}

func Load(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	var c Config
	if e = yaml.Unmarshal(b, &c); e != nil {
		return c, e
	}
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	if c.Issuer == "" {
		return c, fmt.Errorf("issuer required")
	}
	if c.Addr == "" {
		c.Addr = ":8080"
	}
	if c.RedisAddr == "" {
		c.RedisAddr = "memory"
	}
	c.AccessTokenTTL = time.Hour
	c.CodeTTL = time.Minute
	if len(c.Providers) == 0 {
		return c, fmt.Errorf("at least one provider required")
	}
	seenProviders := map[string]bool{}
	for i := range c.Providers {
		p := &c.Providers[i]
		p.Name = strings.TrimSpace(p.Name)
		p.Type = strings.ToLower(strings.TrimSpace(p.Type))
		if p.Name == "" || seenProviders[p.Name] {
			return c, fmt.Errorf("provider name must be unique and non-empty")
		}
		seenProviders[p.Name] = true
		if p.Type != "github" && p.Type != "google" {
			return c, fmt.Errorf("unsupported provider type %q", p.Type)
		}
		if p.ClientID == "" || p.ClientSecret == "" {
			return c, fmt.Errorf("provider %s credentials are required", p.Name)
		}
	}
	seenClients := map[string]bool{}
	for i := range c.Clients {
		cl := &c.Clients[i]
		cl.ID = strings.TrimSpace(cl.ID)
		if cl.ID == "" || seenClients[cl.ID] {
			return c, fmt.Errorf("client id must be unique and non-empty")
		}
		seenClients[cl.ID] = true
		if len(cl.RedirectURIs) == 0 {
			return c, fmt.Errorf("client %s requires redirect_uris", cl.ID)
		}
		for _, ru := range cl.RedirectURIs {
			if strings.TrimSpace(ru) == "" {
				return c, fmt.Errorf("client %s contains empty redirect_uri", cl.ID)
			}
		}
		if cl.Policy != "" {
			if _, ok := c.Policies[cl.Policy]; !ok {
				return c, fmt.Errorf("client %s references unknown policy %s", cl.ID, cl.Policy)
			}
		}
	}
	return c, nil
}
