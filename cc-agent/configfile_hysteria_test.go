package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigPersisterWritesProtocolSpecificUserFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	initial := map[string]any{
		"inbounds": []any{
			map[string]any{"tag": "vless-in", "settings": map[string]any{"clients": []any{}}},
			map[string]any{"tag": "hysteria-in", "settings": map[string]any{"version": 2, "clients": []any{}}},
		},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
	}
	data, _ := json.Marshal(initial)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	store := NewUserStore(&Config{DataDir: dir})
	store.Sync([]*User{{ID: "11111111-2222-4333-8444-555555555555", Email: "alice"}})
	p := NewConfigPersister(path, []InboundEntry{
		{Tag: "vless-in", Protocol: "vless", Flow: "xtls-rprx-vision"},
		{Tag: "hysteria-in", Protocol: "hysteria"},
	}, store)
	changed, err := p.Flush()
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !changed {
		t.Fatal("expected config change")
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Settings struct {
				Clients []map[string]any `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(out, &root); err != nil {
		t.Fatal(err)
	}
	if got := root.Inbounds[0].Settings.Clients[0]["id"]; got != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("VLESS id = %#v", got)
	}
	if got := root.Inbounds[0].Settings.Clients[0]["flow"]; got != "xtls-rprx-vision" {
		t.Fatalf("VLESS flow = %#v", got)
	}
	if got := root.Inbounds[1].Settings.Clients[0]["auth"]; got != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("Hysteria auth = %#v", got)
	}
	if _, hasID := root.Inbounds[1].Settings.Clients[0]["id"]; hasID {
		t.Fatal("Hysteria client must use auth, not id")
	}
}
