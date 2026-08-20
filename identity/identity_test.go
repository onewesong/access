package identity

import (
	"context"
	"github.com/edgefn/auth-center/provider"
	"github.com/edgefn/auth-center/store"
	"testing"
)

func TestResolveLinksVerifiedEmail(t *testing.T) {
	s := Service{Store: store.NewMemory()}
	a, e := s.Resolve(context.Background(), "github", provider.User{Subject: "42", Email: "User@Example.com", EmailVerified: true, Name: "User"})
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.Resolve(context.Background(), "google", provider.User{Subject: "google-sub", Email: "user@example.com", EmailVerified: true, Name: "User G"})
	if e != nil {
		t.Fatal(e)
	}
	if a.ID != b.ID {
		t.Fatalf("accounts were not linked: %s != %s", a.ID, b.ID)
	}
}

func TestLinkRejectsIdentityConflict(t *testing.T) {
	s := Service{Store: store.NewMemory()}
	a, e := s.Resolve(context.Background(), "github", provider.User{Subject: "a", Email: "a@example.com", EmailVerified: true})
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.Resolve(context.Background(), "google", provider.User{Subject: "b", Email: "b@example.com", EmailVerified: true})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Link(context.Background(), b.ID, "github", "a", "a@example.com"); e == nil {
		t.Fatal("expected identity conflict")
	}
	if e = s.Link(context.Background(), a.ID, "github", "new", "a@example.com"); e != nil {
		t.Fatal(e)
	}
}
