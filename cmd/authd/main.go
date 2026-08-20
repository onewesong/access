package main

import (
	"github.com/edgefn/auth-center/config"
	"github.com/edgefn/auth-center/provider"
	"github.com/edgefn/auth-center/server"
	"github.com/edgefn/auth-center/store"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	path := "config.example.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	cfg, e := config.Load(path)
	if e != nil {
		log.Error("config", "error", e)
		os.Exit(1)
	}
	var ps []provider.IdentityProvider
	for _, p := range cfg.Providers {
		switch p.Type {
		case "github":
			ps = append(ps, provider.NewGitHub(p.ClientID, p.ClientSecret, cfg.Issuer+"/oauth/callback/"+p.Name))
		case "google":
			ps = append(ps, provider.NewGoogle(p.ClientID, p.ClientSecret, cfg.Issuer+"/oauth/callback/"+p.Name))
		}
	}
	var st store.Store = store.NewMemory()
	if cfg.RedisAddr != "memory" {
		st = store.NewRedis(cfg.RedisAddr)
	}
	log.Info("auth center started", "addr", cfg.Addr)
	if e = http.ListenAndServe(cfg.Addr, server.New(cfg, st, ps).Handler()); e != nil {
		log.Error("server", "error", e)
	}
}
