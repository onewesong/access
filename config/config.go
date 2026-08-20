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
}
type Policy struct {
	AllowedProviders []string `yaml:"allowed_providers"`
	EmailDomains     []string `yaml:"email_domains"`
	AllowedRoles     []string `yaml:"allowed_roles"`
}
type Config struct {
	Issuer         string            `yaml:"issuer"`
	Addr           string            `yaml:"addr"`
	CookieSecure   bool              `yaml:"cookie_secure"`
	RedisAddr      string            `yaml:"redis_addr"`
	SigningKey     string            `yaml:"signing_key"`
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
	return c, nil
}
