// A finite, read-only Xray MAIN probe for a trusted local launcher.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	handler "github.com/xtls/xray-core/app/proxyman/command"
	router "github.com/xtls/xray-core/app/router/command"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/protobuf/proto"
)

const (
	apiAddress    = "127.0.0.1:61000"
	schema        = "native-xray-main-proof/v1"
	maxInput      = 2 << 20
	maxReply      = 4 << 20
	maxUsers      = 10000 // Across the whole request.
	maxInbounds   = 16
	maxRoutes     = 32
	rpcDeadline   = 4 * time.Second
	childDeadline = 8 * time.Second // Also bounds pipe reads/writes.
)

var (
	invalidPlan = errors.New("INVALID_PLAN")
	validTag    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	validEmail  = regexp.MustCompile(`^[!-~]{1,254}$`)
	validLabel  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

type request struct {
	Version       string          `json:"version"`
	NamedInbounds []namedInbound  `json:"namedInbounds"`
	Routes        []expectedRoute `json:"routes"`
}

type namedInbound struct {
	Tag   string     `json:"tag"`
	Users []identity `json:"users"`
}

type identity struct {
	Email string  `json:"email"`
	UUID  string  `json:"uuid"`
	Flow  *string `json:"flow"`
	Level *uint32 `json:"level"`
}

type expectedRoute struct {
	Context     routeContext `json:"context"`
	OutboundTag string       `json:"outboundTag"`
}

type routeContext struct {
	InboundTag   string  `json:"inboundTag"`
	Network      string  `json:"network"`
	TargetPort   uint16  `json:"targetPort"`
	TargetDomain *string `json:"targetDomain"`
	TargetIP     *string `json:"targetIP"`
}

type user struct {
	id    uuid.UUID
	flow  string
	level uint32
}

type inboundCheck struct {
	tag   string
	users map[string]user
}

type routeCheck struct {
	context  *router.RoutingContext
	outbound string
}

type plan struct {
	inbounds []inboundCheck
	routes   []routeCheck
}

type countReceipt struct {
	HandlerCount    int64 `json:"handlerCount"`
	EnumeratedNamed int   `json:"enumeratedNamed"`
}

type receipt struct {
	Version        string         `json:"version"`
	UserScope      string         `json:"userScope"`
	NamedInbounds  []countReceipt `json:"namedInbounds"`
	RoutesVerified int            `json:"routesVerified"`
}

// The standard decoder accepts duplicate keys and case-folds struct fields.
// Walk this small, closed schema first to reject ambiguous keys and nulls.
func strictJSON(d *json.Decoder, depth int) bool {
	if depth > 8 {
		return false
	}
	tok, err := d.Token()
	if err != nil || tok == nil {
		return false
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return false
			}
			switch name {
			case "version", "namedInbounds", "tag", "users", "email", "uuid", "flow", "level",
				"routes", "context", "inboundTag", "network", "targetPort", "targetDomain", "targetIP", "outboundTag":
			default:
				return false
			}
			seen[name] = true
			if !strictJSON(d, depth+1) {
				return false
			}
		}
	case json.Delim('['):
		for d.More() {
			if !strictJSON(d, depth+1) {
				return false
			}
		}
	default:
		return true
	}
	_, err = d.Token() // Closing delimiter, checked by the decoder.
	return err == nil
}

func readPlan(r io.Reader) (plan, error) {
	var req request
	raw, err := io.ReadAll(io.LimitReader(r, maxInput+1))
	if err != nil || len(raw) > maxInput || !utf8.Valid(raw) {
		return plan{}, invalidPlan
	}
	shape := json.NewDecoder(bytes.NewReader(raw))
	shape.UseNumber()
	if !strictJSON(shape, 0) {
		return plan{}, invalidPlan
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF || req.Version != schema ||
		len(req.NamedInbounds) == 0 || len(req.NamedInbounds) > maxInbounds ||
		len(req.Routes) == 0 || len(req.Routes) > maxRoutes {
		return plan{}, invalidPlan
	}

	var p plan
	tags := make(map[string]bool, len(req.NamedInbounds))
	total := 0
	for _, ib := range req.NamedInbounds {
		total += len(ib.Users)
		if !validTag.MatchString(ib.Tag) || tags[ib.Tag] || ib.Users == nil || total > maxUsers {
			return plan{}, invalidPlan
		}
		tags[ib.Tag] = true
		check := inboundCheck{ib.Tag, make(map[string]user, len(ib.Users))}
		names, ids := map[string]bool{}, map[[16]byte]bool{}
		for _, u := range ib.Users {
			if u.Flow == nil || u.Level == nil {
				return plan{}, invalidPlan
			}
			value, ok := admitIdentity(u.Email, u.UUID, *u.Flow, *u.Level, names, ids)
			if !ok {
				return plan{}, invalidPlan
			}
			check.users[u.Email] = value
		}
		p.inbounds = append(p.inbounds, check)
	}
	for _, route := range req.Routes {
		c := route.Context
		if !tags[c.InboundTag] || !validTag.MatchString(route.OutboundTag) || c.TargetPort == 0 ||
			(c.TargetDomain == nil && c.TargetIP == nil) {
			return plan{}, invalidPlan
		}
		msg := &router.RoutingContext{InboundTag: c.InboundTag, TargetPort: uint32(c.TargetPort)}
		switch c.Network {
		case "tcp":
			msg.Network = xnet.Network_TCP
		case "udp":
			msg.Network = xnet.Network_UDP
		default:
			return plan{}, invalidPlan
		}
		if c.TargetDomain != nil {
			if !isDomain(*c.TargetDomain) {
				return plan{}, invalidPlan
			}
			msg.TargetDomain = *c.TargetDomain
		}
		if c.TargetIP != nil {
			ip, err := netip.ParseAddr(*c.TargetIP)
			if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.String() != *c.TargetIP {
				return plan{}, invalidPlan
			}
			msg.TargetIPs = [][]byte{ip.AsSlice()}
		}
		for _, prior := range p.routes {
			if proto.Equal(prior.context, msg) {
				return plan{}, invalidPlan
			}
		}
		p.routes = append(p.routes, routeCheck{msg, route.OutboundTag})
	}
	return p, nil
}

func isDomain(s string) bool {
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !validLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// Check the raw UUID as well as Xray's effective VLESS lookup key. Two
// different names/UUIDs sharing one lookup key cannot prove two accounts.
func admitIdentity(email, rawID, flow string, level uint32, names map[string]bool, ids map[[16]byte]bool) (user, bool) {
	if !validEmail.MatchString(email) || (flow != "" && flow != "xtls-rprx-vision") || len(rawID) != 36 {
		return user{}, false
	}
	id, err := uuid.ParseString(rawID)
	name, key := strings.ToLower(email), vless.ProcessUUID(id)
	if err != nil || id.String() != rawID || names[name] || ids[key] {
		return user{}, false
	}
	names[name], ids[key] = true, true
	return user{id, flow, level}, true
}

type userReader interface {
	GetInboundUsersCount(context.Context, *handler.GetInboundUserRequest, ...grpc.CallOption) (*handler.GetInboundUsersCountResponse, error)
	GetInboundUsers(context.Context, *handler.GetInboundUserRequest, ...grpc.CallOption) (*handler.GetInboundUserResponse, error)
}

type routeReader interface {
	TestRoute(context.Context, *router.TestRouteRequest, ...grpc.CallOption) (*router.RoutingContext, error)
}

func exactNamedUsers(rows []*protocol.User, expected map[string]user) bool {
	if len(rows) != len(expected) {
		return false
	}
	names, ids := map[string]bool{}, map[[16]byte]bool{}
	for _, row := range rows {
		account := new(vless.Account)
		if row == nil || len(row.ProtoReflect().GetUnknown()) != 0 || row.Account == nil ||
			len(row.Account.ProtoReflect().GetUnknown()) != 0 ||
			row.Account.Type != string(account.ProtoReflect().Descriptor().FullName()) ||
			proto.Unmarshal(row.Account.Value, account) != nil || len(account.ProtoReflect().GetUnknown()) != 0 {
			return false
		}
		live, valid := admitIdentity(row.Email, account.Id, account.Flow, row.Level, names, ids)
		want, found := expected[row.Email]
		if !valid || !found || want != live {
			return false
		}
	}
	return true
}

func verify(ctx context.Context, h userReader, r routeReader, p plan) (receipt, error) {
	out := receipt{Version: schema, UserScope: "named-vless-email-index"}
	for i, ib := range p.inbounds {
		req := &handler.GetInboundUserRequest{Tag: ib.tag} // No email filter.
		want := int64(len(ib.users))
		readCount := func() (int64, error) {
			res, err := h.GetInboundUsersCount(ctx, req)
			if err != nil || res == nil || len(res.ProtoReflect().GetUnknown()) != 0 {
				return 0, fmt.Errorf("USER_COUNT_UNAVAILABLE %d", i)
			}
			if res.Count != want {
				return 0, fmt.Errorf("USER_COUNT_MISMATCH %d", i)
			}
			return res.Count, nil
		}
		if _, err := readCount(); err != nil {
			return receipt{}, err
		}
		res, err := h.GetInboundUsers(ctx, req)
		if err != nil || res == nil || len(res.ProtoReflect().GetUnknown()) != 0 {
			return receipt{}, fmt.Errorf("USERS_UNAVAILABLE %d", i)
		}
		if !exactNamedUsers(res.Users, ib.users) {
			return receipt{}, fmt.Errorf("NAMED_USERS_MISMATCH %d", i)
		}
		count, err := readCount()
		if err != nil {
			return receipt{}, err
		}
		out.NamedInbounds = append(out.NamedInbounds, countReceipt{count, len(res.Users)})
	}
	for i, route := range p.routes {
		got, err := r.TestRoute(ctx, &router.TestRouteRequest{
			RoutingContext: route.context,
			FieldSelectors: []string{"inbound", "network", "ip_target", "port_target", "domain", "outbound"},
			PublishResult:  false,
		})
		if err != nil || got == nil {
			return receipt{}, fmt.Errorf("TEST_ROUTE_UNAVAILABLE %d", i)
		}
		want := proto.CloneOf(route.context)
		want.OutboundTag = route.outbound
		// outbound also selects outbound_group on these cores. Reject any
		// nonempty group, unexpected field or changed/missing context.
		if !proto.Equal(got, want) {
			return receipt{}, fmt.Errorf("TEST_ROUTE_MISMATCH %d", i)
		}
		out.RoutesVerified++
	}
	if ctx.Err() != nil {
		return receipt{}, errors.New("PROOF_DEADLINE")
	}
	return out, nil
}

func prove(p plan) (receipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcDeadline)
	defer cancel()
	var dialed atomic.Bool
	conn, err := grpc.NewClient("passthrough:///"+apiAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithNoProxy(), grpc.WithDisableServiceConfig(), grpc.WithDisableRetry(),
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			if address != apiAddress || !dialed.CompareAndSwap(false, true) {
				return nil, errors.New("DIAL_REFUSED")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp4", apiAddress)
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxReply), grpc.MaxCallSendMsgSize(4096)),
	)
	if err != nil {
		return receipt{}, errors.New("API_UNAVAILABLE")
	}
	out, err := verify(ctx, handler.NewHandlerServiceClient(conn), router.NewRoutingServiceClient(conn), p)
	if closeErr := conn.Close(); closeErr != nil && err == nil {
		return receipt{}, errors.New("API_CLOSE_FAILED")
	}
	return out, err
}

func main() {
	// No environment-driven gRPC diagnostics in the private proof channel.
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, io.Discard))
	stop := time.AfterFunc(childDeadline, func() { os.Exit(124) })
	defer stop.Stop()
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, invalidPlan)
		os.Exit(2)
	}
	p, err := readPlan(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out, err := prove(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if json.NewEncoder(os.Stdout).Encode(out) != nil {
		os.Exit(1)
	}
}
