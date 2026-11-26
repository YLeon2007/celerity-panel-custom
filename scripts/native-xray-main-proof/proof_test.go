package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	handler "github.com/xtls/xray-core/app/proxyman/command"
	router "github.com/xtls/xray-core/app/router/command"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const (
	fixtureUUID  = "00000000-0000-4000-8000-000000000001"
	fixtureUser  = `{"email":"fixture@main.invalid","uuid":"` + fixtureUUID + `","flow":"xtls-rprx-vision","level":7}`
	fixtureRoute = `{"context":{"inboundTag":"vless-in","network":"tcp","targetPort":443,` +
		`"targetDomain":"Choice.example.invalid","targetIP":"192.0.2.8"},"outboundTag":"selected"}`
	fixturePlan = `{"version":"native-xray-main-proof/v1","namedInbounds":[{"tag":"vless-in","users":[` +
		fixtureUser + `]}],"routes":[` + fixtureRoute + `]}`
)

func TestReadPlanRejectsOutsideContract(t *testing.T) {
	sub := func(old, new string) string { return strings.Replace(fixturePlan, old, new, 1) }
	for _, c := range []struct{ name, input string }{
		{"trailing-json", fixturePlan + `{}`},
		{"oversize", fixturePlan + strings.Repeat(" ", maxInput)},
		{"external-dial", sub(`"version":`, `"server":"192.0.2.1:61000","version":`)},
		{"stats-publish", sub(`"outboundTag":`, `"publishResult":true,"outboundTag":`)},
		{"wrong-key-case", sub(`"targetPort":`, `"TargetPort":`)},
		{"duplicate-key", sub(`"targetPort":`, `"targetPort":999,"targetPort":`)},
		{"escaped-duplicate-key", sub(`"level":`, `"l\u0065vel":9,"level":`)},
		{"wrong-version", sub(schema, "native-xray-main-proof/v2")},
		{"null-field", sub(`"level":7`, `"level":null`)},
		{"missing-flow", sub(`"flow":"xtls-rprx-vision",`, ``)},
		{"anonymous-expectation", sub("fixture@main.invalid", "")},
		{"noncanonical-uuid", sub(fixtureUUID, "fixture")},
		{"duplicate-folded-email", sub(fixtureUser, fixtureUser+","+strings.NewReplacer("fixture@", "Fixture@", fixtureUUID, "00000000-0000-4000-8000-000000000002").Replace(fixtureUser))},
		{"duplicate-effective-uuid", sub(fixtureUser, fixtureUser+","+strings.NewReplacer("fixture@", "other@", "-4000-", "-4999-").Replace(fixtureUser))},
		{"unknown-inbound", sub(`"inboundTag":"vless-in"`, `"inboundTag":"other"`)},
		{"bad-port", sub(`:443`, `:65536`)},
		{"bad-network", sub(`"tcp"`, `"raw"`)},
		{"mapped-ip", sub(`192.0.2.8`, `::ffff:192.0.2.8`)},
		{"bad-domain", sub(`Choice.example.invalid`, `https://example.invalid`)},
		{"duplicate-route", sub(fixtureRoute, fixtureRoute+","+strings.Replace(fixtureRoute, "selected", "other", 1))},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := readPlan(strings.NewReader(c.input)); err != invalidPlan {
				t.Fatal("input not rejected")
			}
		})
	}
}

func fixtureRoutingContext() *router.RoutingContext {
	return &router.RoutingContext{InboundTag: "vless-in", Network: xnet.Network_TCP, TargetPort: 443,
		TargetDomain: "Choice.example.invalid", TargetIPs: [][]byte{{192, 0, 2, 8}}}
}

type script struct {
	t        *testing.T
	calls    []string
	counts   []int64
	rows     []*protocol.User
	edit     func(*router.RoutingContext)
	routeErr error
}

func (s *script) userCall(req *handler.GetInboundUserRequest, method string) {
	s.t.Helper()
	if !proto.Equal(req, &handler.GetInboundUserRequest{Tag: "vless-in"}) {
		s.t.Fatal("not an exact unfiltered inbound request")
	}
	s.calls = append(s.calls, method)
}

func (s *script) GetInboundUsersCount(_ context.Context, req *handler.GetInboundUserRequest, _ ...grpc.CallOption) (*handler.GetInboundUsersCountResponse, error) {
	s.userCall(req, "count")
	count := s.counts[0]
	s.counts = s.counts[1:]
	return &handler.GetInboundUsersCountResponse{Count: count}, nil
}

func (s *script) GetInboundUsers(_ context.Context, req *handler.GetInboundUserRequest, _ ...grpc.CallOption) (*handler.GetInboundUserResponse, error) {
	s.userCall(req, "enumerate")
	return &handler.GetInboundUserResponse{Users: s.rows}, nil
}

func (s *script) TestRoute(_ context.Context, req *router.TestRouteRequest, _ ...grpc.CallOption) (*router.RoutingContext, error) {
	s.calls = append(s.calls, "route")
	want := &router.TestRouteRequest{
		RoutingContext: fixtureRoutingContext(),
		FieldSelectors: []string{"inbound", "network", "ip_target", "port_target", "domain", "outbound"},
	}
	if !proto.Equal(req, want) {
		s.t.Fatal("not an exact bounded TestRoute request")
	}
	res := fixtureRoutingContext()
	res.OutboundTag = "selected"
	if s.edit != nil {
		s.edit(res)
	}
	return res, s.routeErr
}

func TestVerifyRequiresExactReads(t *testing.T) {
	p, err := readPlan(strings.NewReader(fixturePlan))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, err, sequence string
		set                 func(*script)
	}{
		{"exact", "", "count enumerate count route", nil},
		{"count-first", "USER_COUNT_MISMATCH 0", "count", func(s *script) { s.counts[0] = 2 }},
		{"count-last", "USER_COUNT_MISMATCH 0", "count enumerate count", func(s *script) { s.counts[1] = 0 }},
		{"enumeration-short", "NAMED_USERS_MISMATCH 0", "count enumerate", func(s *script) { s.rows = nil }},
		{"wrong-account-type", "NAMED_USERS_MISMATCH 0", "count enumerate", func(s *script) { s.rows[0].Account.Type = "not-vless" }},
		{"wrong-account-bytes", "NAMED_USERS_MISMATCH 0", "count enumerate", func(s *script) { s.rows[0].Account.Value = []byte{0xff} }},
		{"empty-account", "NAMED_USERS_MISMATCH 0", "count enumerate", func(s *script) { s.rows[0] = nil }},
		{"rpc-error-redacted", "TEST_ROUTE_UNAVAILABLE 0", "count enumerate count route", func(s *script) { s.routeErr = errors.New(fixtureUUID) }},
		{"route-different-inbound", "TEST_ROUTE_MISMATCH 0", "count enumerate count route", func(s *script) {
			s.edit = func(r *router.RoutingContext) { r.InboundTag = "other" }
		}},
		{"route-different-ip", "TEST_ROUTE_MISMATCH 0", "count enumerate count route", func(s *script) {
			s.edit = func(r *router.RoutingContext) { r.TargetIPs[0][3]++ }
		}},
		{"route-different-port", "TEST_ROUTE_MISMATCH 0", "count enumerate count route", func(s *script) {
			s.edit = func(r *router.RoutingContext) { r.TargetPort++ }
		}},
		{"route-group-present", "TEST_ROUTE_MISMATCH 0", "count enumerate count route", func(s *script) {
			s.edit = func(r *router.RoutingContext) { r.OutboundGroupTags = []string{"balancer"} }
		}},
		{"route-unknown-field", "TEST_ROUTE_MISMATCH 0", "count enumerate count route", func(s *script) {
			s.edit = func(r *router.RoutingContext) { r.ProtoReflect().SetUnknown([]byte{0x7a, 0x00}) }
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := script{t: t, counts: []int64{1, 1}, rows: []*protocol.User{{Email: "fixture@main.invalid", Level: 7,
				Account: serial.ToTypedMessage(&vless.Account{Id: fixtureUUID, Flow: "xtls-rprx-vision"})}}}
			if c.set != nil {
				c.set(&s)
			}
			got, err := verify(context.Background(), &s, &s, p)
			if strings.Join(s.calls, " ") != c.sequence {
				t.Fatal("unexpected RPC sequence")
			}
			if c.err == "" {
				want := receipt{Version: schema, UserScope: "named-vless-email-index", NamedInbounds: []countReceipt{{1, 1}}, RoutesVerified: 1}
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("missing exact success receipt")
				}
			} else if err == nil || err.Error() != c.err || !reflect.DeepEqual(got, receipt{}) {
				t.Fatal("invalid response did not fail closed without a receipt")
			}
		})
	}
}
