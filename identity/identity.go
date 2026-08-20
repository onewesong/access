package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/edgefn/auth-center/provider"
	"github.com/edgefn/auth-center/store"
)

type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Name          string    `json:"name"`
	Avatar        string    `json:"avatar"`
	Disabled      bool      `json:"disabled"`
	RevokedBefore time.Time `json:"revoked_before"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (s Service) Disable(ctx context.Context, userID string) error {
	var u User
	if err := s.Store.Get(ctx, "user:"+userID, &u); err != nil {
		return err
	}
	u.Disabled = true
	u.UpdatedAt = time.Now().UTC()
	return s.Store.Set(ctx, "user:"+userID, u, 0)
}

type Identity struct {
	Provider  string    `json:"provider"`
	Subject   string    `json:"subject"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type Service struct{ Store store.Store }

func (s Service) Unlink(ctx context.Context, providerName, subject string) error {
	return s.Store.Delete(ctx, "identity:"+providerName+":"+subject)
}
func (s Service) Link(ctx context.Context, userID, providerName, subject, email string) error {
	var u User
	if e := s.Store.Get(ctx, "user:"+userID, &u); e != nil {
		return e
	}
	var existing Identity
	if e := s.Store.Get(ctx, "identity:"+providerName+":"+subject, &existing); e == nil && existing.UserID != userID {
		return fmt.Errorf("identity already linked to another user")
	}
	return s.Store.Set(ctx, "identity:"+providerName+":"+subject, Identity{Provider: providerName, Subject: subject, UserID: userID, Email: email, CreatedAt: time.Now().UTC()}, 0)
}

func (s Service) Resolve(ctx context.Context, providerName string, p provider.User) (User, error) {
	identityKey := "identity:" + providerName + ":" + p.Subject
	var linked Identity
	if err := s.Store.Get(ctx, identityKey, &linked); err == nil {
		var u User
		if err := s.Store.Get(ctx, "user:"+linked.UserID, &u); err != nil {
			return User{}, err
		}
		return s.update(ctx, u, p)
	}

	var u User
	emailKey := "email:" + strings.ToLower(strings.TrimSpace(p.Email))
	if p.EmailVerified && p.Email != "" && s.Store.Get(ctx, emailKey, &u) == nil {
		if err := s.link(ctx, providerName, p, u.ID); err != nil {
			return User{}, err
		}
		return s.update(ctx, u, p)
	}

	now := time.Now().UTC()
	u = User{ID: randomID(), Email: p.Email, EmailVerified: p.EmailVerified, Name: p.Name, Avatar: p.Avatar, CreatedAt: now, UpdatedAt: now}
	if err := s.Store.Set(ctx, "user:"+u.ID, u, 0); err != nil {
		return User{}, err
	}
	if p.EmailVerified && p.Email != "" {
		if err := s.Store.Set(ctx, emailKey, u, 0); err != nil {
			return User{}, err
		}
	}
	if err := s.link(ctx, providerName, p, u.ID); err != nil {
		return User{}, err
	}
	return u, nil
}

func (s Service) link(ctx context.Context, providerName string, p provider.User, userID string) error {
	return s.Store.Set(ctx, "identity:"+providerName+":"+p.Subject, Identity{Provider: providerName, Subject: p.Subject, UserID: userID, Email: p.Email, CreatedAt: time.Now().UTC()}, 0)
}

func (s Service) update(ctx context.Context, u User, p provider.User) (User, error) {
	if p.Email != "" {
		u.Email = p.Email
	}
	if p.EmailVerified {
		u.EmailVerified = true
	}
	if p.Name != "" {
		u.Name = p.Name
	}
	if p.Avatar != "" {
		u.Avatar = p.Avatar
	}
	u.UpdatedAt = time.Now().UTC()
	if err := s.Store.Set(ctx, "user:"+u.ID, u, 0); err != nil {
		return User{}, err
	}
	if u.EmailVerified && u.Email != "" {
		if err := s.Store.Set(ctx, "email:"+strings.ToLower(strings.TrimSpace(u.Email)), u, 0); err != nil {
			return User{}, err
		}
	}
	return u, nil
}

func randomID() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
