package main

import (
	"testing"

	hysteria_account "github.com/xtls/xray-core/proxy/hysteria/account"
)

func TestAccountForInboundUsesHysteriaAccount(t *testing.T) {
	u := &User{ID: "11111111-2222-4333-8444-555555555555", Email: "alice"}

	typed := accountForInbound(InboundEntry{Tag: "hysteria-in", Protocol: "hysteria"}, u)
	if typed == nil {
		t.Fatal("expected typed Hysteria account")
	}
	if got, want := typed.Type, "xray.proxy.hysteria.account.Account"; got != want {
		t.Fatalf("account type = %q, want %q", got, want)
	}
	instance, err := typed.GetInstance()
	if err != nil {
		t.Fatalf("decode typed account: %v", err)
	}
	account, ok := instance.(*hysteria_account.Account)
	if !ok {
		t.Fatalf("decoded type = %T, want *account.Account", instance)
	}
	if got, want := account.Auth, u.ID; got != want {
		t.Fatalf("decoded auth = %q, want %q", got, want)
	}
}

func TestAccountForInboundDefaultsToVless(t *testing.T) {
	u := &User{ID: "11111111-2222-4333-8444-555555555555", Email: "alice"}
	typed := accountForInbound(InboundEntry{Tag: "vless-in", Flow: "xtls-rprx-vision"}, u)
	if got, want := typed.Type, "xray.proxy.vless.Account"; got != want {
		t.Fatalf("legacy account type = %q, want %q", got, want)
	}
}
