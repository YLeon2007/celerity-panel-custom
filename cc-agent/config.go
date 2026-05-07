package main

import (
	"encoding/json"
	"os"
)

type TLSConfig struct {
	Enabled bool   `json:"enabled"`
	Cert    string `json:"cert"`
	Key     string `json:"key"`
}

// InboundEntry describes a single Xray VLESS inbound the agent has to
// add/remove users to/from. Flow is the per-inbound XTLS flow (empty for
// transports that do not support flow, e.g. WebSocket/gRPC/XHTTP).
type InboundEntry struct {
	Tag  string `json:"tag"`
	Flow string `json:"flow"`
}

type Config struct {
	Listen  string    `json:"listen"`
	Token   string    `json:"token"`
	XrayAPI string    `json:"xray_api"`
	DataDir string    `json:"data_dir"`
	TLS     TLSConfig `json:"tls"`

	// InboundTag is the legacy single-inbound tag. It is kept for backward
	// compatibility with old panels that do not write the Inbounds array.
	InboundTag string `json:"inbound_tag"`

	// Inbounds is the new multi-inbound configuration. When set, AddUser /
	// RemoveUser iterate over every entry and apply the per-tag Flow.
	// When empty, the loader synthesizes a single entry from InboundTag and
	// flow is resolved from the running Xray config (best-effort).
	Inbounds []InboundEntry `json:"inbounds,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Listen:     "0.0.0.0:62080",
		XrayAPI:    "127.0.0.1:61000",
		InboundTag: "vless-in",
		DataDir:    "/var/lib/cc-agent",
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Backward compatibility: if the new Inbounds array is missing but the
	// legacy InboundTag is present, synthesize a single entry. Flow is
	// resolved from the running Xray config (best-effort) so XTLS-Vision
	// clients keep working when the panel only writes the legacy field.
	if len(cfg.Inbounds) == 0 && cfg.InboundTag != "" {
		flow := ""
		if probed, ok := probeFlowFromXrayConfig(cfg.InboundTag); ok {
			flow = probed
		}
		cfg.Inbounds = []InboundEntry{{Tag: cfg.InboundTag, Flow: flow}}
	}

	return cfg, nil
}
