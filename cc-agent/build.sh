#!/bin/bash
# Build cc-agent for Linux AMD64 (typical VPS)
# Run: bash build.sh
set -e

echo "=== Building cc-agent ==="

# Fetch dependencies
go mod tidy

# Build static Linux AMD64 binary compatible with older distros.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cc-agent-linux-amd64 .

# Build static Linux ARM64 binary.
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o cc-agent-linux-arm64 .

echo "Done: cc-agent-linux-amd64 built ($(du -sh cc-agent-linux-amd64 | cut -f1))"
echo "Done: cc-agent-linux-arm64 built ($(du -sh cc-agent-linux-arm64 | cut -f1))"
