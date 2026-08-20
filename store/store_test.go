package store

import (
	"context"
	"testing"
	"time"
)

func TestMemoryConsumeOnce(t *testing.T) {
	m := NewMemory()
	if e := m.Set(context.Background(), "k", map[string]string{"v": "1"}, time.Minute); e != nil {
		t.Fatal(e)
	}
	var v map[string]string
	if e := m.Consume(context.Background(), "k", &v); e != nil || v["v"] != "1" {
		t.Fatalf("consume=%v %#v", e, v)
	}
	if e := m.Consume(context.Background(), "k", &v); e != ErrNotFound {
		t.Fatalf("second consume=%v", e)
	}
}
