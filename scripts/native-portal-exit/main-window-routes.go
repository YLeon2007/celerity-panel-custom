// Native MAIN-window fixture only. Build against the pinned cc-agent module.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	router "github.com/xtls/xray-core/app/router/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("fixture requires one API port")
	}
	port, err := strconv.ParseUint(os.Args[1], 10, 16)
	if err != nil || port == 0 {
		log.Fatal("invalid fixture API port")
	}
	interfaces, err := net.Interfaces()
	parent := os.Getenv("C3_CUTOVER_PARENT_NETNS")
	own, nsErr := os.Readlink("/proc/self/ns/net")
	if err != nil || nsErr != nil || parent == "" || own == parent || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		log.Fatal("fixture requires isolated loopback")
	}
	conn, err := grpc.NewClient("passthrough:///127.0.0.1:"+strconv.FormatUint(port, 10),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal("fixture RoutingService unavailable")
	}
	defer conn.Close()
	client := router.NewRoutingServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var tags []string
	for _, domain := range []string{"exit-choice.example.invalid", "default-choice.example.invalid"} {
		reply, err := client.TestRoute(ctx, &router.TestRouteRequest{
			RoutingContext: &router.RoutingContext{InboundTag: "vless-in", TargetDomain: domain},
		}, grpc.WaitForReady(true))
		if err != nil || reply == nil || (reply.OutboundTag != "a" && reply.OutboundTag != "b") {
			log.Fatal("fixture TestRoute unproved")
		}
		tags = append(tags, reply.OutboundTag)
	}
	if err := json.NewEncoder(os.Stdout).Encode(tags); err != nil {
		log.Fatal("fixture result unavailable")
	}
}
