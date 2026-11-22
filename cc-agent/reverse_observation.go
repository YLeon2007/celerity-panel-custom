package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	command "github.com/xtls/xray-core/app/proxyman/command"
	stats "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	reverseObservationWindow  = 11 * time.Second // Native idle heartbeat is ~10s on Xray 26.11.9.
	reverseObservationTimeout = 13 * time.Second
	vlessInboundType          = "xray.proxy.vless.inbound.Config"
)

var (
	reverseLinkID    = regexp.MustCompile(`^[a-f0-9]{24}$`)
	reverseIdentity  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	reverseChallenge = regexp.MustCompile(`^[a-f0-9]{32}$`)
	reverseUUID      = regexp.MustCompile(`^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
	reverseEmail     = regexp.MustCompile(`^rproof-[a-f0-9]{24}-[a-f0-9]{64}@rebuild\.invalid$`)
)

func isReverseObservationEmail(email string) bool {
	return reverseEmail.MatchString(email)
}

type reverseObservationSubject struct {
	linkID, identity string
	port             uint32
}

func (s reverseObservationSubject) email() string {
	return "rproof-" + s.linkID + "-" + s.identity + "@rebuild.invalid"
}

func (s reverseObservationSubject) connector() string { return "rebuild-rp-conn-" + s.linkID[16:] }
func (s reverseObservationSubject) egress() string    { return "rebuild-rp-egress-" + s.linkID[16:] }

type reverseObservationReply struct {
	Version     int    `json:"version"`
	LinkID      string `json:"linkId"`
	Port        uint32 `json:"port"`
	Challenge   string `json:"challenge"`
	Established bool   `json:"established"`
}

func (a *API) handleReverseObservation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet || len(r.URL.RawQuery) > 160 {
		jsonErr(w, http.StatusBadRequest, "invalid reverse observation request")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	linkID, port, identity, challenge := r.PathValue("id"), q.Get("port"), q.Get("identity"), q.Get("challenge")
	p, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || len(q) != 3 || len(q["port"]) != 1 || len(q["identity"]) != 1 || len(q["challenge"]) != 1 ||
		!reverseLinkID.MatchString(linkID) || !reverseIdentity.MatchString(identity) || !reverseChallenge.MatchString(challenge) ||
		portErr != nil || p == 0 || strconv.FormatUint(p, 10) != port {
		jsonErr(w, http.StatusBadRequest, "invalid reverse observation request")
		return
	}
	// Use only the configured node-local API, never a network destination derived from the request.
	host, _, err := net.SplitHostPort(a.cfg.XrayAPI)
	if err != nil || !net.ParseIP(host).IsLoopback() || a.xrayClient == nil {
		jsonErr(w, http.StatusServiceUnavailable, "reverse observation unavailable")
		return
	}
	select {
	case a.reverseObservations <- struct{}{}:
		defer func() { <-a.reverseObservations }()
	default:
		jsonErr(w, http.StatusServiceUnavailable, "reverse observation busy")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), reverseObservationTimeout)
	defer cancel()
	subject := reverseObservationSubject{linkID: linkID, identity: identity, port: uint32(p)}
	established, err := a.xrayClient.observeReverse(ctx, subject)
	if err != nil || ctx.Err() != nil {
		// Xray errors and protobufs can contain account credentials. Never forward or log them.
		jsonErr(w, http.StatusServiceUnavailable, "reverse observation unavailable")
		return
	}
	jsonOK(w, reverseObservationReply{Version: 1, LinkID: linkID, Port: uint32(p), Challenge: challenge, Established: established})
}

// Keep each observation on the same loopback gRPC transport. A reconnect to a
// replacement core cannot combine its counters with the previous baseline.
type reverseRPC struct {
	current    peer.Peer
	connection string
}

func (r *reverseRPC) matches() bool {
	p := r.current
	if p.Addr == nil || p.LocalAddr == nil {
		return false
	}
	key := p.LocalAddr.String() + " " + p.Addr.String()
	if r.connection == "" {
		r.connection = key
	}
	return key == r.connection
}

func (c *XrayClient) observeReverse(ctx context.Context, s reverseObservationSubject) (bool, error) {
	rpc := &reverseRPC{}
	if ok, err := c.reverseScope(ctx, rpc, s); !ok || err != nil {
		return false, err
	}
	name := "user>>>" + s.email() + ">>>traffic>>>downlink"
	read := func() (int64, error) {
		resp, err := c.stats.GetStats(ctx, &stats.GetStatsRequest{Name: name}, grpc.Peer(&rpc.current))
		if err != nil {
			return 0, err
		}
		if !rpc.matches() || resp.GetStat().GetName() != name || resp.GetStat().GetValue() < 0 {
			return 0, fmt.Errorf("invalid reverse counter")
		}
		return resp.GetStat().GetValue(), nil
	}
	before, err := read()
	if status.Code(err) == codes.NotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	timer := time.NewTimer(reverseObservationWindow)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	if ok, err := c.reverseScope(ctx, rpc, s); !ok || err != nil {
		return false, err
	}
	after, err := read()
	// Existing billing may reset counters. A reset can mask growth, but it
	// cannot fabricate a strictly larger value on this same counter/transport.
	return after > before && err == nil, err
}

func (s reverseObservationSubject) matchesUser(u *protocol.User) bool {
	if u.GetEmail() != s.email() || u.GetLevel() != 0 {
		return false
	}
	var account vless.Account
	if !decodeReverseSetting(u.GetAccount(), "xray.proxy.vless.Account", &account) ||
		account.GetReverse().GetTag() != s.egress() || account.GetFlow() != "" {
		return false
	}
	id := strings.ToLower(account.GetId())
	return reverseUUID.MatchString(id) && fmt.Sprintf("%x", sha256.Sum256([]byte(id))) == s.identity
}

func decodeReverseSetting(value *serial.TypedMessage, kind string, dst proto.Message) bool {
	return value.GetType() == kind && proto.Unmarshal(value.GetValue(), dst) == nil
}

// The stats key is process-global by email. Verify the configured connector
// and check the exact live email lookup across managed account-bearing
// inbounds. Email-free accounts cannot write to this key and need no census.
func (c *XrayClient) reverseScope(ctx context.Context, rpc *reverseRPC, s reverseObservationSubject) (bool, error) {
	in, err := c.proxyman.ListInbounds(ctx, &command.ListInboundsRequest{}, grpc.Peer(&rpc.current))
	if err != nil {
		return false, err
	}
	if !rpc.matches() || len(in.GetInbounds()) > 64 {
		return false, nil
	}
	found := false
	tags := make(map[string]bool, len(in.GetInbounds()))
	for _, ib := range in.GetInbounds() {
		tag, setting := ib.GetTag(), ib.GetProxySettings()
		if tag == "" || tags[tag] {
			return false, nil
		}
		tags[tag] = true
		if tag == s.connector() {
			var receiver proxyman.ReceiverConfig
			var listener vlessin.Config
			if !decodeReverseSetting(ib.GetReceiverSettings(), "xray.app.proxyman.ReceiverConfig", &receiver) ||
				!decodeReverseSetting(setting, vlessInboundType, &listener) || listener.GetDecryption() != "none" || len(listener.GetFallbacks()) != 0 {
				return false, nil
			}
			stream, ports := receiver.GetStreamSettings(), receiver.GetPortList().GetRange()
			if len(ports) != 1 || ports[0].GetFrom() != s.port || ports[0].GetTo() != s.port ||
				stream.GetProtocolName() != "tcp" || stream.GetSecurityType() != "xray.transport.internet.reality.Config" {
				return false, nil
			}
			for _, u := range listener.GetClients() {
				if strings.EqualFold(u.GetEmail(), s.email()) {
					if found || !s.matchesUser(u) {
						return false, nil
					}
					found = true
				}
			}
		} else {
			switch setting.GetType() {
			case "xray.proxy.dokodemo.Config", "xray.proxy.socks.ServerConfig": // No dispatcher user-email stats.
				continue
			case vlessInboundType, "xray.proxy.vmess.inbound.Config":
			default: // Unknown account namespace: cannot establish uniqueness.
				return false, nil
			}
		}
		users, err := c.proxyman.GetInboundUsers(ctx, &command.GetInboundUserRequest{Tag: tag, Email: s.email()}, grpc.Peer(&rpc.current))
		if err != nil {
			return false, err
		}
		if !rpc.matches() {
			return false, nil
		}
		rows := users.GetUsers()
		if tag == s.connector() {
			if len(rows) != 1 || !s.matchesUser(rows[0]) {
				return false, nil
			}
		} else if len(rows) != 0 && (len(rows) != 1 || rows[0].GetEmail() != "" || rows[0].GetAccount() != nil) {
			// Some cores represent a failed exact lookup by one empty protobuf user.
			return false, nil
		}
	}
	if !found {
		return false, nil
	}
	out, err := c.proxyman.ListOutbounds(ctx, &command.ListOutboundsRequest{}, grpc.Peer(&rpc.current))
	if err != nil || !rpc.matches() {
		return false, err
	}
	matches := 0
	for _, ob := range out.GetOutbounds() {
		if ob.GetTag() == s.egress() {
			if ob.GetSenderSettings() != nil || ob.GetProxySettings() != nil {
				return false, nil // Not a dynamically registered native reverse handler.
			}
			matches++
		}
	}
	return matches == 1, nil
}
