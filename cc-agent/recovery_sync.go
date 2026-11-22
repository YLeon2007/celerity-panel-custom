package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	command "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

func (a *API) handleRecoverySync(ctx context.Context, w http.ResponseWriter, lease *mutationLease, users []*User, desired map[string]*User) {
	// Do not queue another snapshot across the transition to normal operation.
	if !a.recoverySync.TryLock() {
		jsonErr(w, http.StatusServiceUnavailable, "Recovery sync already in progress")
		return
	}
	defer a.recoverySync.Unlock()
	if !a.userStore.needsFullSync() {
		jsonErr(w, http.StatusServiceUnavailable, "Recovery sync superseded; retry with a fresh snapshot")
		return
	}
	added, removed, err := a.xrayClient.reconcileRecoveryUsers(ctx, desired)
	if err != nil {
		log.Printf("[sync] Recovery incomplete: %v", err)
		jsonErr(w, http.StatusServiceUnavailable, "Recovery sync incomplete; full sync required")
		return
	}
	a.finishSync(w, lease, users, added, removed, 0)
}

type recoveryIdentity struct {
	id    uuid.UUID
	flow  string
	level uint32
}

func (u recoveryIdentity) matches(id uuid.UUID, flow string) bool {
	return u == (recoveryIdentity{id: id, flow: flow})
}

func (c *XrayClient) readRecoveryUsers(ctx context.Context, tag string) (map[string]recoveryIdentity, error) {
	// Unfiltered GetInboundUsers enumerates the VLESS email index. Anonymous
	// clients are not in this index and are outside recovery's mutation scope.
	resp, err := c.proxyman.GetInboundUsers(ctx, &command.GetInboundUserRequest{Tag: tag})
	if err != nil {
		return nil, fmt.Errorf("read users on %q: %w", tag, err)
	}
	if resp == nil {
		return nil, fmt.Errorf("missing users response on %q", tag)
	}
	users := make(map[string]recoveryIdentity, len(resp.Users))
	names := make(map[string]bool, len(resp.Users))
	ids := make(map[[16]byte]bool, len(resp.Users))
	for _, u := range resp.Users {
		if u == nil || u.Email == "" || u.Account == nil {
			return nil, fmt.Errorf("incomplete named user on %q", tag)
		}
		account, err := u.Account.GetInstance()
		acc, ok := account.(*vless.Account)
		if err != nil || !ok {
			return nil, fmt.Errorf("unreadable VLESS account on %q", tag)
		}
		id, err := uuid.ParseString(acc.Id)
		name, key := strings.ToLower(u.Email), vless.ProcessUUID(id)
		if err != nil || names[name] || ids[key] {
			return nil, fmt.Errorf("invalid or ambiguous VLESS identity on %q", tag)
		}
		names[name], ids[key] = true, true
		users[u.Email] = recoveryIdentity{id: id, flow: acc.Flow, level: u.Level}
	}
	return users, nil
}

func (c *XrayClient) reconcileRecoveryUsers(ctx context.Context, desired map[string]*User) (int, int, error) {
	if c == nil || c.proxyman == nil || len(c.inbounds) == 0 {
		return 0, 0, fmt.Errorf("HandlerService or managed inbounds unavailable")
	}

	// Use Xray's identity rules (case-folded email, parsed UUID) before any
	// writes. Duplicate runtime UUID keys can silently displace other users.
	want := make(map[string]uuid.UUID, len(desired))
	names := make(map[string]bool, len(desired))
	ids := make(map[[16]byte]bool, len(desired))
	for email, u := range desired {
		id, err := uuid.ParseString(u.ID)
		name, key := strings.ToLower(email), vless.ProcessUUID(id)
		if err != nil || names[name] || ids[key] {
			return 0, 0, fmt.Errorf("invalid or ambiguous VLESS identity in panel snapshot")
		}
		names[name], ids[key] = true, true
		want[email] = id
	}

	// Census every managed inbound before any writes. Inbounds may differ;
	// a union would hide missing users and same-name identity drift per tag.
	live := make(map[string]map[string]recoveryIdentity, len(c.inbounds))
	for _, ib := range c.inbounds {
		if _, seen := live[ib.Tag]; ib.Tag == "" || seen {
			return 0, 0, fmt.Errorf("empty or duplicate managed inbound tag")
		}
		users, err := c.readRecoveryUsers(ctx, ib.Tag)
		if err != nil {
			return 0, 0, err
		}
		live[ib.Tag] = users
	}

	addedNames, removedNames := make(map[string]bool), make(map[string]bool)
	for _, ib := range c.inbounds {
		current := live[ib.Tag]
		// Remove stale and changed users first, including renamed UUIDs and
		// ID swaps. Unlike the normal path, no RPC errors are benign here.
		for email, old := range current {
			if id, ok := want[email]; ok && old.matches(id, ib.Flow) {
				continue
			}
			_, err := c.proxyman.AlterInbound(ctx, &command.AlterInboundRequest{
				Tag: ib.Tag, Operation: serial.ToTypedMessage(&command.RemoveUserOperation{Email: email}),
			})
			if err != nil {
				return 0, 0, fmt.Errorf("remove user on %q: %w", ib.Tag, err)
			}
			removedNames[email] = true
		}
		for email, id := range want {
			if old, ok := current[email]; ok && old.matches(id, ib.Flow) {
				continue
			}
			_, err := c.proxyman.AlterInbound(ctx, &command.AlterInboundRequest{
				Tag: ib.Tag, Operation: serial.ToTypedMessage(&command.AddUserOperation{User: &protocol.User{
					Level: 0, Email: email,
					Account: serial.ToTypedMessage(&vless.Account{Id: desired[email].ID, Flow: ib.Flow}),
				}}),
			})
			if err != nil {
				return 0, 0, fmt.Errorf("add user on %q: %w", ib.Tag, err)
			}
			addedNames[email] = true
		}
	}

	// Do not publish the snapshot on mutation acknowledgements alone.
	for _, ib := range c.inbounds {
		actual, err := c.readRecoveryUsers(ctx, ib.Tag)
		if err != nil {
			return 0, 0, err
		}
		if len(actual) != len(want) {
			return 0, 0, fmt.Errorf("users readback differs on %q", ib.Tag)
		}
		for email, id := range want {
			if got, ok := actual[email]; !ok || !got.matches(id, ib.Flow) {
				return 0, 0, fmt.Errorf("user identity readback differs on %q", ib.Tag)
			}
		}
	}
	return len(addedNames), len(removedNames), ctx.Err()
}
