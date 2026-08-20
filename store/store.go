package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/redis/go-redis/v9"
	"sync"
	"time"
)

var ErrNotFound = errors.New("not found")

type Store interface {
	Set(context.Context, string, any, time.Duration) error
	Get(context.Context, string, any) error
	Delete(context.Context, string) error
	Consume(context.Context, string, any) error
	Ping(context.Context) error
}
type Memory struct {
	mu sync.Mutex
	m  map[string]entry
}
type entry struct {
	b   []byte
	exp time.Time
}

func NewMemory() *Memory { return &Memory{m: map[string]entry{}} }
func (m *Memory) Set(_ context.Context, k string, v any, ttl time.Duration) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	m.mu.Lock()
	m.m[k] = entry{b, time.Now().Add(ttl)}
	m.mu.Unlock()
	return nil
}
func (m *Memory) Get(_ context.Context, k string, v any) error {
	m.mu.Lock()
	x, ok := m.m[k]
	if ok && time.Now().After(x.exp) {
		delete(m.m, k)
		ok = false
	}
	m.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	return json.Unmarshal(x.b, v)
}
func (m *Memory) Delete(_ context.Context, k string) error {
	m.mu.Lock()
	delete(m.m, k)
	m.mu.Unlock()
	return nil
}
func (m *Memory) Consume(ctx context.Context, k string, v any) error {
	m.mu.Lock()
	x, ok := m.m[k]
	if ok {
		delete(m.m, k)
	}
	m.mu.Unlock()
	if !ok || time.Now().After(x.exp) {
		return ErrNotFound
	}
	return json.Unmarshal(x.b, v)
}
func (m *Memory) Ping(context.Context) error { return nil }

type Redis struct{ c *redis.Client }

func NewRedis(addr string) *Redis { return &Redis{redis.NewClient(&redis.Options{Addr: addr})} }
func (r *Redis) Set(ctx context.Context, k string, v any, ttl time.Duration) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return r.c.Set(ctx, k, b, ttl).Err()
}
func (r *Redis) Get(ctx context.Context, k string, v any) error {
	b, e := r.c.Get(ctx, k).Bytes()
	if e == redis.Nil {
		return ErrNotFound
	}
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func (r *Redis) Delete(ctx context.Context, k string) error { return r.c.Del(ctx, k).Err() }
func (r *Redis) Consume(ctx context.Context, k string, v any) error {
	b, e := r.c.GetDel(ctx, k).Bytes()
	if e == redis.Nil {
		return ErrNotFound
	}
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func (r *Redis) Ping(ctx context.Context) error { return r.c.Ping(ctx).Err() }
