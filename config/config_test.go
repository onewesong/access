package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsDuplicateClient(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.yaml")
	data := []byte("issuer: http://localhost\nproviders:\n- name: github\n  type: github\n  client_id: id\n  client_secret: secret\nclients:\n- id: app\n  redirect_uris: [http://a]\n- id: app\n  redirect_uris: [http://b]\n")
	if e := os.WriteFile(p, data, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(p); e == nil {
		t.Fatal("expected duplicate client error")
	}
}
