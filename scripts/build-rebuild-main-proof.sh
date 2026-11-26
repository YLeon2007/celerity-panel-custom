#!/bin/sh
# Build the panel-side payload for both remote host architectures.
# Usage: sh scripts/build-rebuild-main-proof.sh /absolute/app/libexec
set -eu
cd "$(dirname "$0")/.."
case "${1:-}" in
    /*) output=$1 ;;
    *) printf '%s\n' 'An absolute output directory is required.' >&2; exit 2 ;;
esac
mkdir -p "$output"
for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go -C cc-agent build -mod=readonly -trimpath -ldflags='-s -w' \
        -o "$output/rebuild-main-proof-linux-$arch" ../scripts/native-xray-main-proof/proof.go
done