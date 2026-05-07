package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	proxyman_command "github.com/xtls/xray-core/app/proxyman/command"
	stats_command "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	vless "github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// xrayConfigPath is the canonical location written by nodeSetup.installXray.
const xrayConfigPath = "/usr/local/etc/xray/config.json"

// probeFlowFromXrayConfig reads the on-disk Xray config, finds the inbound
// with the given tag and returns the flow value from its first client.
// This is a best-effort backward-compat helper for legacy panels that did
// not write the explicit per-tag Flow into cc-agent config.json.
func probeFlowFromXrayConfig(tag string) (string, bool) {
	data, err := os.ReadFile(xrayConfigPath)
	if err != nil {
		return "", false
	}

	var parsed struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Settings struct {
				Clients []struct {
					Flow string `json:"flow"`
				} `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", false
	}

	for _, ib := range parsed.Inbounds {
		if ib.Tag == tag && len(ib.Settings.Clients) > 0 {
			return ib.Settings.Clients[0].Flow, true
		}
	}
	return "", false
}

// XrayClient wraps the Xray gRPC API. It owns the list of VLESS inbounds the
// agent must keep in sync — every AddUser/RemoveUser call iterates over them.
// The per-tag Flow value is used as-is when calling AlterInbound, so flow=""
// is sent for transports where flow is not supported (WS/gRPC/XHTTP).
type XrayClient struct {
	conn     *grpc.ClientConn
	proxyman proxyman_command.HandlerServiceClient
	stats    stats_command.StatsServiceClient
	inbounds []InboundEntry
}

func NewXrayClient(cfg *Config) (*XrayClient, error) {
	conn, err := grpc.NewClient(cfg.XrayAPI,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc.NewClient: %w", err)
	}

	// LoadConfig guarantees Inbounds is populated (synthesizes a single
	// entry from the legacy InboundTag when missing). No further fallback
	// is needed here.
	return &XrayClient{
		conn:     conn,
		proxyman: proxyman_command.NewHandlerServiceClient(conn),
		stats:    stats_command.NewStatsServiceClient(conn),
		inbounds: cfg.Inbounds,
	}, nil
}

// AddUser adds a VLESS user to every configured Xray inbound via gRPC.
// Flow is taken from the per-inbound configuration; the value of u.Flow
// is intentionally ignored — the agent is the source of truth here.
func (c *XrayClient) AddUser(ctx context.Context, u *User) error {
	if len(c.inbounds) == 0 {
		return fmt.Errorf("AddUser %s: no inbounds configured", u.Email)
	}
	var firstErr error
	for _, ib := range c.inbounds {
		_, err := c.proxyman.AlterInbound(ctx, &proxyman_command.AlterInboundRequest{
			Tag: ib.Tag,
			Operation: serial.ToTypedMessage(&proxyman_command.AddUserOperation{
				User: &protocol.User{
					Level: 0,
					Email: u.Email,
					Account: serial.ToTypedMessage(&vless.Account{
						Id:   u.ID,
						Flow: ib.Flow,
					}),
				},
			}),
		})
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("AddUser %s on %s: %w", u.Email, ib.Tag, err)
		}
	}
	return firstErr
}

// RemoveUser removes a user from every configured Xray inbound via gRPC.
func (c *XrayClient) RemoveUser(ctx context.Context, email string) error {
	if len(c.inbounds) == 0 {
		return fmt.Errorf("RemoveUser %s: no inbounds configured", email)
	}
	var firstErr error
	for _, ib := range c.inbounds {
		_, err := c.proxyman.AlterInbound(ctx, &proxyman_command.AlterInboundRequest{
			Tag: ib.Tag,
			Operation: serial.ToTypedMessage(&proxyman_command.RemoveUserOperation{
				Email: email,
			}),
		})
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("RemoveUser %s on %s: %w", email, ib.Tag, err)
		}
	}
	return firstErr
}

// QueryStats fetches traffic stats from Xray matching the given pattern.
// An empty pattern returns all stats (users, inbounds, outbounds) in one call.
// reset=true atomically clears the matched counters in Xray.
func (c *XrayClient) QueryStats(ctx context.Context, pattern string, reset bool) (map[string]int64, error) {
	resp, err := c.stats.QueryStats(ctx, &stats_command.QueryStatsRequest{
		Pattern: pattern,
		Reset_:  reset,
	})
	if err != nil {
		return nil, fmt.Errorf("QueryStats: %w", err)
	}

	result := make(map[string]int64, len(resp.Stat))
	for _, stat := range resp.Stat {
		result[stat.Name] = stat.Value
	}
	return result, nil
}

func (c *XrayClient) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
}
