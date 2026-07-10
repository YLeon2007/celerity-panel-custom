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

// AccessLogsConfig configures the opt-in Xray access-log tail/ship module.
// When Enabled is false (or the whole block is absent) the module stays inert
// and the agent behaves exactly like older versions — this preserves
// backward/downgrade compatibility with panels that never write this block.
type AccessLogsConfig struct {
	Enabled bool `json:"enabled"`

	// Path to the Xray access log file the agent tails.
	Path string `json:"path"`

	// IngestURL is the full panel endpoint that receives NDJSON+gzip batches.
	IngestURL string `json:"ingest_url"`

	// IngestToken is the per-node Bearer credential sent with every batch.
	IngestToken string `json:"ingest_token"`

	// InsecureTLS disables TLS verification for the ingest connection. Used
	// only when the panel serves a self-signed certificate (mirrors the
	// existing agent TLS behavior).
	InsecureTLS bool `json:"insecure_tls"`

	// SpoolMaxBytes caps the on-disk batch spool. Oldest batches are dropped
	// past this cap (with a dropped-events counter) so a long panel outage
	// cannot fill the node disk.
	SpoolMaxBytes int64 `json:"spool_max_bytes"`

	// BatchMaxEvents / FlushIntervalSeconds control batching cadence.
	BatchMaxEvents       int `json:"batch_max_events"`
	FlushIntervalSeconds int `json:"flush_interval_seconds"`

	// FileMaxBytes triggers agent-managed rotation: once the access log grows
	// beyond this and has been fully read, the agent truncates it in place.
	FileMaxBytes int64 `json:"file_max_bytes"`
}

// applyDefaults fills unset access-log fields with conservative defaults.
func (c *AccessLogsConfig) applyDefaults() {
	if c.Path == "" {
		c.Path = "/var/log/xray/access.log"
	}
	if c.SpoolMaxBytes <= 0 {
		c.SpoolMaxBytes = 200 * 1024 * 1024 // 200 MB
	}
	if c.BatchMaxEvents <= 0 {
		c.BatchMaxEvents = 500
	}
	if c.FlushIntervalSeconds <= 0 {
		c.FlushIntervalSeconds = 5
	}
	if c.FileMaxBytes <= 0 {
		c.FileMaxBytes = 64 * 1024 * 1024 // 64 MB
	}
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

	// AccessLogs configures the opt-in access-log shipping module. Absent =
	// disabled; older panels never write it, so downgrade stays safe.
	AccessLogs AccessLogsConfig `json:"access_logs"`
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

	cfg.AccessLogs.applyDefaults()

	return cfg, nil
}
