package policy

import (
	"github.com/edgefn/auth-center/config"
	"github.com/edgefn/auth-center/provider"
	"strings"
)

func Allow(p config.Policy, u provider.User) bool {
	providerName, _ := u.Claims["provider"].(string)
	if len(p.AllowedProviders) > 0 && !contains(p.AllowedProviders, providerName) {
		return false
	}
	if len(p.EmailDomains) > 0 {
		ok := false
		parts := strings.Split(u.Email, "@")
		if len(parts) == 2 {
			for _, d := range p.EmailDomains {
				if strings.EqualFold(strings.TrimSpace(d), parts[1]) {
					ok = true
				}
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
func contains(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(strings.TrimSpace(x), v) {
			return true
		}
	}
	return false
}
