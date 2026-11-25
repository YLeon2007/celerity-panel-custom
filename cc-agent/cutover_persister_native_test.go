package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	router "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/common/uuid"
	"google.golang.org/grpc"
)

// This is a characterization of the unmodified persister, not an acceptance
// test for Apply. Invoke only in the private namespace described in tests/.
func TestNativeCutoverPersisterBoundary(t *testing.T) {
	parent := os.Getenv("C3_CUTOVER_PARENT_NETNS")
	if parent == "" {
		t.Skip("explicit private native fixture required")
	}
	own, err := os.Readlink("/proc/self/ns/net")
	if err != nil || !strings.HasPrefix(parent, "net:[") || parent == own || !strings.HasPrefix(own, "net:[") {
		t.Fatal("network namespace not proved")
	}
	if _, err := os.Lstat("/etc/resolv.conf"); !os.IsNotExist(err) {
		t.Fatal("fixture must not mount host resolver")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" ||
		interfaces[0].Flags&(net.FlagLoopback|net.FlagUp) != net.FlagLoopback|net.FlagUp {
		t.Fatal("fixture must have only live loopback")
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			t.Fatal("loopback addresses unavailable")
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil || !ip.IsLoopback() {
				t.Fatal("nonloopback address in fixture")
			}
		}
	}
	const core = "/tools/xray"
	fd, err := os.Open(core)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	_, hashErr := io.Copy(digest, fd)
	closeErr := fd.Close()
	switch fingerprint := fmt.Sprintf("%x", digest.Sum(nil)); {
	case hashErr != nil || closeErr != nil:
		t.Fatal("Xray digest unavailable")
	case fingerprint == "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed":
		t.Log("Xray 26.3.27")
	case fingerprint == "e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d":
		t.Log("Xray 26.11.9")
	default:
		t.Fatal("unexpected fixture Xray binary")
	}

	t.Run("client-only-flush-from-current-image", func(t *testing.T) {
		cutoverPersisterCase(t, core, "clients")
	})
	t.Run("old-image-flush-lands-after-positive-verification", func(t *testing.T) {
		cutoverPersisterCase(t, core, "unfenced")
	})
	t.Run("joined-stop-drains-the-same-pending-publish", func(t *testing.T) {
		cutoverPersisterCase(t, core, "stopped")
	})
}

func cutoverPersisterCase(t *testing.T, core, mode string) {
	root := t.TempDir()
	boot := filepath.Join(root, "config.json")
	reserve := func() net.Listener {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	apiSocket, subscriberSocket := reserve(), reserve()
	apiAddress := apiSocket.Addr().String()
	apiPort := apiSocket.Addr().(*net.TCPAddr).Port
	subscriberPort := subscriberSocket.Addr().(*net.TCPAddr).Port
	if err := apiSocket.Close(); err != nil {
		t.Fatal(err)
	}
	if err := subscriberSocket.Close(); err != nil {
		t.Fatal(err)
	}
	const tag = "vless-in"
	const destination = "fixture.invalid"
	const email = "subscriber@fixture.invalid"
	const userID = "1b70e97d-2e48-48f3-ba2e-094a1486545e"
	id, err := uuid.ParseString(userID)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{XrayAPI: apiAddress, DataDir: root, Inbounds: []InboundEntry{{Tag: tag}}, Token: "fixture-token"}
	store := NewUserStore(cfg)
	t.Cleanup(func() {
		if err := store.Stop(); err != nil {
			t.Error(err)
		}
	})
	p := NewConfigPersister(boot, cfg.Inbounds, store)
	client, err := NewXrayClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.conn.Close() })
	api := &API{cfg: cfg, userStore: store, persister: p, xrayClient: client}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	routes := router.NewRoutingServiceClient(client.conn)
	image := func(exit string, users []*User) []byte {
		return []byte(fmt.Sprintf(`{"log":{"loglevel":"none"},
		  "api":{"tag":"api","services":["HandlerService","RoutingService"]},
		  "inbounds":[{"tag":"api-in","protocol":"dokodemo-door","listen":"127.0.0.1","port":%d,"settings":{"address":"127.0.0.1"}},
		              {"tag":"%s","protocol":"vless","listen":"127.0.0.1","port":%d,"settings":{"decryption":"none","clients":%s}}],
		  "outbounds":[{"tag":"exit-a","protocol":"blackhole"},{"tag":"exit-b","protocol":"blackhole"}],
		  "routing":{"rules":[{"type":"field","ruleTag":"api","inboundTag":["api-in"],"outboundTag":"api"},
		                        {"type":"field","ruleTag":"select-exit","inboundTag":["%s"],"domain":["full:%s"],"outboundTag":"%s"}]}}`,
			apiPort, tag, subscriberPort, cutoverTestJSON(t, buildConfigClients(users, "")), tag, destination, exit))
	}
	project := func(raw []byte) []byte {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			t.Fatal(err)
		}
		for _, value := range doc["inbounds"].([]any) {
			in := value.(map[string]any)
			if _, managed := p.managedFlows()[in["tag"].(string)]; managed {
				delete(in["settings"].(map[string]any), "clients")
			}
		}
		return cutoverTestJSON(t, doc)
	}
	readBoot := func() []byte {
		raw, err := os.ReadFile(boot)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	publish := func(raw []byte) {
		if err := atomicWriteFile(boot, raw); err != nil {
			t.Fatal(err)
		}
	}
	start := func() (*exec.Cmd, func()) {
		cmd := exec.Command(core, "run", "-c", boot)
		cmd.Dir = root
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		stop := func() {
			once.Do(func() {
				_ = cmd.Process.Signal(syscall.SIGTERM)
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				select {
				case err := <-done:
					if err != nil {
						t.Error("Xray did not exit successfully")
					}
				case <-time.After(3 * time.Second):
					_ = cmd.Process.Kill()
					<-done
					t.Error("Xray did not exit in time")
				}
			})
		}
		t.Cleanup(stop)
		return cmd, stop
	}
	verifyLive := func(cmd *exec.Cmd, exit string, users map[string]recoveryIdentity) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result, err := routes.TestRoute(ctx, &router.TestRouteRequest{RoutingContext: &router.RoutingContext{
			InboundTag: tag, TargetDomain: destination,
		}}, grpc.WaitForReady(true))
		if err != nil || result.GetOutboundTag() != exit {
			t.Fatalf("TestRoute did not select %s: %v", exit, err)
		}
		listed, err := routes.ListRule(ctx, &router.ListRuleRequest{})
		if err != nil || len(listed.GetRules()) != 2 || listed.Rules[1].GetRuleTag() != "select-exit" || listed.Rules[1].GetTag() != exit {
			t.Fatalf("routing tag/action readback did not select %s: %v", exit, err)
		}
		have, err := client.readRecoveryUsers(ctx, tag)
		if err != nil || !reflect.DeepEqual(have, users) {
			t.Fatal("HandlerService users differ from fixture allocation")
		}
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", cmd.Process.Pid)); err != nil || exe != core {
			t.Fatal("Xray process identity changed")
		}
	}
	addUser := func() {
		req := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"id":"`+userID+`","email":"`+email+`"}`))
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != http.StatusOK || store.Count() != 1 {
			t.Fatalf("actual agent handler failed to admit user, status %d", res.Code)
		}
	}
	expected := map[string]recoveryIdentity{email: {id: id}}
	old, candidate := image("exit-a", nil), image("exit-b", []*User{{ID: userID, Email: email}})
	if mode == "clients" {
		publish(image("exit-b", nil))
		proc, _ := start()
		verifyLive(proc, "exit-b", map[string]recoveryIdentity{})
		addUser()
		before := readBoot()
		if _, err := p.Flush(); err != nil {
			t.Fatal(err)
		}
		after := readBoot()
		if bytes.Equal(before, after) || !bytes.Equal(project(after), project(candidate)) {
			t.Fatal("expected a client-only rewrite with identical topology projection")
		}
		verifyLive(proc, "exit-b", expected)
		return
	}

	publish(old)
	first, stopFirst := start()
	verifyLive(first, "exit-a", map[string]recoveryIdentity{})
	addUser()
	verifyLive(first, "exit-a", expected)
	parked, release := make(chan struct{}), make(chan struct{})
	var unpark sync.Once
	letWrite := func() { unpark.Do(func() { close(release) }) }
	defer letWrite()
	p.writeFile = func(path string, data []byte) error {
		close(parked)
		<-release
		return atomicWriteFile(path, data)
	}
	flushed := make(chan struct{})
	var flushErr error
	go func() {
		defer close(flushed)
		_, flushErr = p.Flush()
	}()
	join := func() {
		letWrite()
		select {
		case <-flushed:
		case <-time.After(3 * time.Second):
			t.Fatal("original persister did not finish")
		}
	}
	t.Cleanup(join)
	select {
	case <-parked:
	case <-time.After(3 * time.Second):
		t.Fatal("persister did not reach its native write boundary")
	}
	if mode == "stopped" {
		// Reproduce the old writer at exactly the same boundary. The real Stop
		// must wait for it, unlike an unrelated flock or a boot readback.
		p.debounce = time.Hour
		go p.run()
		began, joined := make(chan struct{}), make(chan error, 1)
		go func() {
			close(began)
			joined <- p.Stop()
		}()
		<-began
		runtime.Gosched()
		select {
		case <-joined:
			t.Fatal("Stop acknowledged while an old write was still parked")
		default:
		}
		join()
		select {
		case err := <-joined:
			if err != nil || flushErr != nil {
				t.Fatal("agent flush did not drain")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Stop did not finish after the original writer drained")
		}
		if bytes.Equal(readBoot(), old) || !bytes.Equal(project(readBoot()), project(old)) {
			t.Fatal("final flush did not retain the fresh user on A")
		}
		if _, err := p.Flush(); err != errPersisterStopped {
			t.Fatal("old persister accepted another flush after Stop")
		}
		publish(candidate)
		stopFirst()
		second, stopSecond := start()
		verifyLive(second, "exit-b", expected)
		replacement := NewConfigPersister(boot, cfg.Inbounds, store)
		if changed, err := replacement.Flush(); changed || err != nil || !bytes.Equal(project(readBoot()), project(candidate)) {
			t.Fatal("new persister changed the verified topology")
		}
		stopSecond()
		third, _ := start()
		verifyLive(third, "exit-b", expected)
		return
	}

	publish(candidate)
	stopFirst()
	second, stopSecond := start()
	if second.Process.Pid == first.Process.Pid || !bytes.Equal(project(readBoot()), project(candidate)) {
		t.Fatal("cutover boot projection or new PID not proved")
	}
	verifyLive(second, "exit-b", expected)
	if !bytes.Equal(project(readBoot()), project(candidate)) {
		t.Fatal("boot projection drifted before final verification")
	}
	t.Log("candidate verified: boot projection, new PID, ListRule, TestRoute, and HandlerService users")

	join()
	if flushErr != nil {
		t.Fatal(flushErr)
	}
	if !bytes.Equal(project(readBoot()), project(old)) {
		t.Fatal("expected late persister publication to reinstate the old topology")
	}
	if changed, err := p.Flush(); err != nil || changed {
		t.Fatal("expected client set to have converged without repairing topology")
	}
	verifyLive(second, "exit-b", expected)
	stopSecond()
	third, _ := start()
	verifyLive(third, "exit-a", expected)
	t.Log("late flush reverted the boot policy after verification; next start selected the original exit with the same user set")
}

func cutoverTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
