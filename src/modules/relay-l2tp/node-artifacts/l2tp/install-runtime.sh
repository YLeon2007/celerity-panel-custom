#!/usr/bin/env bash
set -Eeuo pipefail

emit_error() {
    local code="$1"
    printf '{"status":"error","code":"%s"}\n' "$code" >&2
}

if [[ "$#" -ne 0 ]]; then
    emit_error 'INVALID_ARGUMENTS'
    exit 64
fi

readonly -a REQUIRED_PACKAGES=(strongswan strongswan-starter xl2tpd ppp nftables)
dpkg_query_path="$(command -v dpkg-query || true)"
apt_get_path="$(command -v apt-get || true)"
if [[ -z "$dpkg_query_path" || -z "$apt_get_path" ]]; then
    emit_error 'DEBIAN_PACKAGE_TOOLS_MISSING'
    exit 69
fi

package_installed() {
    local package="$1"
    local status
    status="$($dpkg_query_path -W '-f=${db:Status-Abbrev}' "$package" 2>/dev/null || true)"
    [[ "$status" == 'ii '* ]]
}

missing_packages=()
for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! package_installed "$package"; then
        missing_packages+=("$package")
    fi
done

changed="${#missing_packages[@]}"
if (( changed > 0 )); then
    if ! DEBIAN_FRONTEND=noninteractive "$apt_get_path" \
        --yes \
        --no-install-recommends \
        --no-remove \
        install \
        "${missing_packages[@]}" >/dev/null 2>&1; then
        emit_error 'RUNTIME_INSTALL_FAILED'
        exit 70
    fi
fi

for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! package_installed "$package"; then
        emit_error 'RUNTIME_PACKAGE_MISSING'
        exit 70
    fi
done

printf '{"status":"ok","changed":%d,"present":%d}\n' \
    "$changed" "${#REQUIRED_PACKAGES[@]}"
