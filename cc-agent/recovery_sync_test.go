package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	command "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc"
)

type recoveryProxyman struct {
	command.HandlerServiceClient
	mu          sync.Mutex
	live        map[string]map[string]*protocol.User
	writes      int
	beforeRead  func(string) error
	beforeWrite func(*command.AlterInboundRequest) error
	ignoreWrite bool
}

func recoveryTestUser(email, id, flow string) *protocol.User {
	return &protocol.User{Email: email, Account: serial.ToTypedMessage(&vless.Account{Id: id, Flow: flow})}
}

func (f *recoveryProxyman) GetInboundUsers(_ context.Context, req *command.GetInboundUserRequest, _ ...grpc.CallOption) (*command.GetInboundUserResponse, error) {
	if req.Email != "" {
		return nil, errors.New("expected unfiltered census")
	}
	if f.beforeRead != nil {
		if err := f.beforeRead(req.Tag); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	users, ok := f.live[req.Tag]
	if !ok {
		return nil, fmt.Errorf("unknown inbound %q", req.Tag)
	}
	resp := &command.GetInboundUserResponse{}
	for _, user := range users {
		resp.Users = append(resp.Users, user)
	}
	return resp, nil
}

func (f *recoveryProxyman) AlterInbound(_ context.Context, req *command.AlterInboundRequest, _ ...grpc.CallOption) (*command.AlterInboundResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.beforeWrite != nil {
		if err := f.beforeWrite(req); err != nil {
			return nil, err
		}
	}
	users, ok := f.live[req.Tag]
	if !ok {
		return nil, fmt.Errorf("unknown inbound %q", req.Tag)
	}
	op, err := req.Operation.GetInstance()
	if err != nil {
		return nil, err
	}
	if !f.ignoreWrite {
		switch op := op.(type) {
		case *command.RemoveUserOperation:
			if users[op.Email] == nil {
				return nil, errors.New("user not found")
			}
			delete(users, op.Email)
		case *command.AddUserOperation:
			for email := range users {
				if strings.EqualFold(email, op.User.Email) {
					return nil, errors.New("user already exists")
				}
			}
			users[op.User.Email] = op.User
		default:
			return nil, errors.New("unexpected operation")
		}
	}
	return &command.AlterInboundResponse{}, nil
}

func recoveryTestAPI(s *UserStore, p *ConfigPersister) (*API, *recoveryProxyman) {
	fake := &recoveryProxyman{live: map[string]map[string]*protocol.User{
		"managed": {"keep": recoveryTestUser("keep", "old", "")},
		"other":   {"unmanaged": recoveryTestUser("unmanaged", "foreign", "")},
	}}
	return &API{cfg: &Config{Token: "fixture"}, userStore: s, persister: p,
		xrayClient: &XrayClient{proxyman: fake, inbounds: []InboundEntry{{Tag: "managed"}}}}, fake
}

func recoveryFixture(t *testing.T) (*API, *recoveryProxyman) {
	t.Helper()
	s, p := startupFiles(t, `{`, populatedConfig)
	t.Cleanup(func() {
		if err := s.Stop(); err != nil {
			t.Error(err)
		}
		if err := p.Stop(); err != nil {
			t.Error(err)
		}
	})
	if !s.needsFullSync() {
		t.Fatal("fixture did not enter recovery")
	}
	return recoveryTestAPI(s, p)
}

func recoveryRequest(a *API, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.handleSync(w, httptest.NewRequest(http.MethodPost, "/sync", body))
	return w
}

func TestRecoverySyncRemovesLiveUsersForExplicitEmptySnapshot(t *testing.T) {
	a, fake := recoveryFixture(t)
	w := recoveryRequest(a, strings.NewReader(`{"users":[]}`))
	if w.Code != 200 || a.userStore.needsFullSync() || fake.writes != 1 || len(fake.live["managed"]) != 0 || len(fake.live["other"]) != 1 {
		t.Fatalf("empty sync did not remove just the live managed user: %d %s", w.Code, w.Body)
	}
}

func TestRecoverySyncReconcilesEachManagedInbound(t *testing.T) {
	a, fake := recoveryFixture(t)
	const flow = "xtls-rprx-vision"
	a.xrayClient.inbounds = append(a.xrayClient.inbounds, InboundEntry{Tag: "extra", Flow: flow})
	fake.live["extra"] = map[string]*protocol.User{
		"keep":  recoveryTestUser("keep", "new", flow),
		"stale": recoveryTestUser("stale", "stale", flow),
	}
	fake.live["managed"]["add"] = recoveryTestUser("add", "add", "")
	w := recoveryRequest(a, strings.NewReader(`{"users":[{"id":"new","email":"keep"},{"id":"add","email":"add","flow":"ignored"}]}`))
	if w.Code != 200 || a.userStore.needsFullSync() || a.userStore.Count() != 2 || fake.writes != 4 {
		t.Fatalf("recovery did not commit the per-inbound diff: %d %s; writes=%d", w.Code, w.Body, fake.writes)
	}
	for _, ib := range a.xrayClient.inbounds {
		users := fake.live[ib.Tag]
		if len(users) != 2 || users["keep"] == nil || users["add"] == nil {
			t.Fatalf("wrong runtime membership on %s", ib.Tag)
		}
		for email, id := range map[string]string{"keep": "new", "add": "add"} {
			got, err := users[email].Account.GetInstance()
			acc, ok := got.(*vless.Account)
			if err != nil || !ok || acc.Id != id || acc.Flow != ib.Flow {
				t.Fatalf("wrong identity or flow for %s on %s", email, ib.Tag)
			}
		}
	}
}

func TestRecoverySyncFailureKeepsGateClosed(t *testing.T) {
	for _, name := range []string{"no client", "no inbounds", "read error on second tag", "malformed census", "write error", "ineffective write"} {
		t.Run(name, func(t *testing.T) {
			a, fake := recoveryFixture(t)
			wantWrites := 0
			switch name {
			case "no client":
				a.xrayClient = nil
			case "no inbounds":
				a.xrayClient.inbounds = nil
			case "read error on second tag":
				a.xrayClient.inbounds = append(a.xrayClient.inbounds, InboundEntry{Tag: "missing"})
			case "malformed census":
				fake.live["managed"]["bad"] = &protocol.User{Email: "bad"}
			case "write error":
				wantWrites = 1
				fake.beforeWrite = func(*command.AlterInboundRequest) error { return errors.New("handler not found") }
			case "ineffective write":
				wantWrites = 1
				fake.ignoreWrite = true
			}
			w := recoveryRequest(a, strings.NewReader(`{"users":[]}`))
			if w.Code != 503 || !a.userStore.needsFullSync() || !a.userStore.GetLastSync().IsZero() || fake.writes != wantWrites || len(fake.live["managed"]) == 0 {
				t.Fatalf("failed recovery opened gate or made unexpected writes: %d %s; writes=%d", w.Code, w.Body, fake.writes)
			}
		})
	}
}

func TestRecoverySyncRetriesFromFreshRuntimeAfterPartialWrite(t *testing.T) {
	a, fake := recoveryFixture(t)
	fake.beforeWrite = func(req *command.AlterInboundRequest) error {
		if req.Operation.Type == serial.GetMessageType(&command.AddUserOperation{}) {
			return errors.New("write unavailable")
		}
		return nil
	}
	const replacement = `{"users":[{"id":"new","email":"keep"}]}`
	w := recoveryRequest(a, strings.NewReader(replacement))
	if w.Code != 503 || !a.userStore.needsFullSync() || len(fake.live["managed"]) != 0 || fake.writes != 2 {
		t.Fatalf("partial replacement did not keep gate closed: %d %s", w.Code, w.Body)
	}
	fake.beforeWrite = nil
	w = recoveryRequest(a, strings.NewReader(replacement))
	if w.Code != 200 || a.userStore.needsFullSync() || fake.live["managed"]["keep"] == nil || fake.writes != 3 {
		t.Fatalf("retry did not reconcile fresh runtime: %d %s", w.Code, w.Body)
	}
}

type recoveryPausedBody struct {
	io.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *recoveryPausedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.Reader.Read(p)
}

func TestRecoverySyncRejectsOverlappingRequestsAcrossGateOpening(t *testing.T) {
	a, fake := recoveryFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once, releaseRead sync.Once
	unblockRead := func() { releaseRead.Do(func() { close(release) }) }
	defer unblockRead()
	fake.beforeRead = func(string) error {
		// Block only the first call, so an unintended parallel census can run.
		first := false
		once.Do(func() { first = true })
		if first {
			close(entered)
			<-release
		}
		return nil
	}
	const full = `{"users":[{"id":"old","email":"keep"}]}`
	winnerDone := make(chan struct{})
	var winner *httptest.ResponseRecorder
	go func() {
		defer close(winnerDone)
		winner = recoveryRequest(a, strings.NewReader(full))
	}()
	awaitStartupSignal(t, entered)
	if w := recoveryRequest(a, strings.NewReader(`{"users":[]}`)); w.Code != 503 {
		t.Fatalf("parallel recovery was not refused: %d %s", w.Code, w.Body)
	}
	if w := recoveryRequest(a, strings.NewReader(`{"users":null}`)); w.Code != 400 {
		t.Fatalf("invalid snapshot was not refused: %d %s", w.Code, w.Body)
	}
	body := &recoveryPausedBody{Reader: strings.NewReader(`{"users":[]}`), entered: make(chan struct{}), release: make(chan struct{})}
	var releaseBody sync.Once
	unblockBody := func() { releaseBody.Do(func() { close(body.release) }) }
	defer unblockBody()
	lateDone := make(chan struct{})
	var late *httptest.ResponseRecorder
	go func() {
		defer close(lateDone)
		late = recoveryRequest(a, body)
	}()
	awaitStartupSignal(t, body.entered)
	unblockRead()
	awaitStartupSignal(t, winnerDone)
	if winner.Code != 200 || a.userStore.needsFullSync() {
		t.Fatalf("full sync did not open gate: %d %s", winner.Code, winner.Body)
	}
	unblockBody()
	awaitStartupSignal(t, lateDone)
	if late.Code != 503 || fake.writes != 0 || a.userStore.Count() != 1 {
		t.Fatalf("in-flight recovery request leaked into normal sync: %d %s", late.Code, late.Body)
	}
	// Fresh normal sync remains name-based and does not query the runtime.
	fake.beforeRead = func(string) error { return errors.New("census unavailable") }
	if w := recoveryRequest(a, strings.NewReader(`{"users":[{"id":"new","email":"keep"}]}`)); w.Code != 200 || fake.writes != 0 {
		t.Fatalf("normal sync semantics changed: %d %s", w.Code, w.Body)
	}
}
