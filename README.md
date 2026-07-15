# C³ CELERITY

⚡ **Fast. Simple. Long-lasting.**

**[English](README.md)** | [Русский](README.ru.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Deploy](https://img.shields.io/badge/deploy-source--based-2563EB)](docs/custom-deploy.md)
[![Self Update](https://img.shields.io/badge/panel-self--update-16A34A)](docs/safe-update.md)
[![Latest release](https://img.shields.io/github/v/release/YLeon2007/celerity-panel-custom?display_name=tag)](https://github.com/YLeon2007/celerity-panel-custom/releases/latest)
[![Node.js](https://img.shields.io/badge/Node.js-20+-339933?logo=node.js&logoColor=white)](package.json)
[![Hysteria](https://img.shields.io/badge/Hysteria-2.x-9B59B6)](https://v2.hysteria.network/)
[![Xray](https://img.shields.io/badge/Xray-VLESS-00ADD8)](https://xtls.github.io/)
[![Telegram](https://img.shields.io/badge/Telegram-Chat-2CA5E0?logo=telegram&logoColor=white)](https://t.me/+JKFdEr7TqvIyOTFi)
[![Support](https://img.shields.io/badge/%E2%99%A5-Support-EC4899)](https://celerity.help)

**C³ CELERITY custom** is a custom build of the original C³ CELERITY panel by Click Connect. It keeps upstream functionality for managing [Hysteria 2](https://v2.hysteria.network/) and [Xray VLESS](https://xtls.github.io/) proxy servers, while adding a reproducible deployment workflow and a place for project-specific improvements.

**Built for practical operations:** source-based deploys, feature branches, safe updates, and one-command installation into `/opt/hysteria-panel`.

<p align="center">
  <img src="docs/dashboard.png" alt="C³ CELERITY Dashboard" width="800">
  <br>
  <em>Dashboard — real-time server monitoring and statistics</em>
</p>

## ⚡ Quick Start — custom public repository

> This custom repository is intended to be deployed from source. The tested production path builds the backend locally with Docker Compose and serves HTTPS through Caddy.

### One-command production install

Point DNS for your panel domain to the target server, then run:

> Supported automatic prerequisite installation: Debian/Ubuntu servers with
> `apt-get` (amd64 or arm64). On other distributions, install Git, curl, OpenSSL,
> Docker Engine and Docker Compose v2 first, then run the installer.

```bash
curl -fsSL \
  https://raw.githubusercontent.com/YLeon2007/celerity-panel-custom/main/scripts/install.sh \
  | sudo -E bash
```

During installation, the script asks interactively:

1. `Укажите домен для панели / Enter panel domain:`
2. `Укажите email администратора домена для получения сертификата Let's Encrypt / Enter domain administrator email for Let's Encrypt certificate:`

For non-interactive installs, you can still pre-set `PANEL_DOMAIN` and `ACME_EMAIL`.

The installer defaults to:

```text
REPO=YLeon2007/celerity-panel-custom
BRANCH=main
INSTALL_DIR=/opt/hysteria-panel
COMPOSE_FILE=docker-compose.yml
```

It will:

- install Docker/Docker Compose if missing;
- clone this repository into `/opt/hysteria-panel`;
- generate `.env` with `ENCRYPTION_KEY`, `SESSION_SECRET`, `MONGO_PASSWORD`, and the HMAC `UPDATER_SECRET` if not provided;
- preserve every existing non-empty `.env` value during an intentional `FORCE=1` repair/update;
- prepare `.env` with mode `0600` and persistent `logs/`, `backups/`, `greenlock.d/`, and Access Logs `data/` directories with restrictive permissions (`data/` and `backups/`: `0700`);
- build and start the backend plus the isolated updater sidecar;
- wait for MongoDB, Redis, backend and HTTPS health, then verify updater HMAC and Docker-socket isolation;
- let Caddy obtain a Let's Encrypt certificate for `PANEL_DOMAIN`.

Open:

```text
https://your-domain/panel
```

### Test or development branch install

```bash
export BRANCH='develop'

curl -fsSL \
  https://raw.githubusercontent.com/YLeon2007/celerity-panel-custom/develop/scripts/install.sh \
  | sudo -E bash
```

### Existing installation safety

If `/opt/hysteria-panel` already exists, the installer creates a backup under:

```text
/opt/hysteria-panel-install-backups/
```

Then it stops. Re-run with `FORCE=1` only for an intentional repair/reinstall. For
routine production updates use **Settings → Maintenance → Panel update** or the
[Safe Production Updates](docs/safe-update.md) procedure.

### Detailed deploy docs

- [Custom deployment](docs/custom-deploy.md)
- [Custom deployment — Russian](docs/custom-deploy-ru.md)
- Updating an existing installation? See [Safe Production Updates](docs/safe-update.md).
- Planning to manage the panel from AI assistants? See [MCP Setup Guide](docs/mcp-user-guide.md).

### Local development

```bash
git clone https://github.com/YLeon2007/celerity-panel-custom.git
cd celerity-panel-custom
docker compose -f docker-compose.local.yml up -d
# Open http://localhost:3000/panel
```

> Local mode has **no TLS** and is not for production. Subscription/share links assume HTTPS, so use it only for UI/API testing.

### Required `.env` variables for manual installs

The installer generates these automatically, but manual deployments must set at least:

```env
PANEL_DOMAIN=panel.example.com
ACME_EMAIL=admin@example.com
ENCRYPTION_KEY=0123456789abcdef0123456789abcdef  # openssl rand -hex 16
SESSION_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  # openssl rand -hex 32
MONGO_PASSWORD=0123456789abcdef                 # openssl rand -hex 16
UPDATER_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  # openssl rand -hex 32
```

---

## 🐳 Dokploy / Traefik (optional, not the primary path)

The supported production path for this custom repository is the source-based installer above (`scripts/install.sh`) and `docker-compose.yml` with Caddy. It keeps the local git checkout in `/opt/hysteria-panel`; **Settings → Maintenance → Panel update** uses an isolated HMAC-authenticated updater sidecar to back up, move to an immutable release tag, rebuild the backend, and retain rollback artifacts. The backend itself has no Docker socket access.

`docker-compose.dokploy.yml` is kept only for operators who intentionally deploy through Dokploy/Traefik and understand the trade-offs:

- Dokploy must build from **this repository/branch** (`build: .`).
- Do **not** switch the backend to `clickdevtech/hysteria-panel:latest` if you need custom changes from this repo (self-update, HAPP iOS routing, custom deploy docs, etc.). That upstream Docker Hub image does not contain this repository's custom commits.
- The self-update flow is designed around a host git checkout. If Dokploy manages the checkout/build lifecycle, updates should normally be performed through git/Dokploy redeploys, not by replacing the backend with an upstream image.

Minimum Dokploy env vars:

- `MONGO_PASSWORD`
- `PANEL_DOMAIN`
- `ACME_EMAIL`
- `ENCRYPTION_KEY`
- `SESSION_SECRET`
- `DOKPLOY_PANEL_HOST` (domain used in the Traefik `Host(...)` rule)
- `DOKPLOY_TRAEFIK_SERVICE_PORT` (Traefik target/backend port, default `3000`)

For normal production servers, prefer the one-command installer and the safe update guide:

- [Custom deployment](docs/custom-deploy.md)
- [Safe Production Updates](docs/safe-update.md)

---

## ✨ Features

- 🔄 **Panel self-update** — isolated updater sidecar, Maintenance-page release check/changelog, authenticated backup/install flow, live progress log, and rollback artifacts
- 🧾 **Opt-in Xray Access Logs** — per-node enablement, durable local spool, ClickHouse delivery, and fail-safe disabled-by-default startup
- 🛠️ **Source-based Caddy deploy** — production compose builds the backend from this repository and proxies HTTPS through Caddy to the stable backend container name
- 🖥 **Web Panel** — Full UI for managing nodes and users
- 🔐 **Dual Protocol** — Hysteria 2 and Xray VLESS on one panel
- 🛡️ **Panel 2FA (TOTP)** — Unified TOTP verification flow for admin login and sensitive security actions
- 🚀 **Auto Node Setup** — Install Hysteria/Xray, certs, port hopping in one click
- 👥 **Server Groups** — Flexible user-to-node mapping
- ⚖️ **Load Balancing** — Distribute users by server load
- 🚫 **Traffic Filtering (ACL)** — Block ads, domains, IPs; route through custom proxies
- 🧩 **Advanced Hysteria Config** — optional ACME challenge options, masquerade modes, resolver, speed test, sniffing, and QUIC tuning
- 📊 **Statistics** — Online users, traffic, server status
- 🟢 **Client indicators** — per-user VPN activity lamp with short-lived Xray telemetry, plus device count and OS summary from HAPP/HWID metadata
- 📱 **Subscriptions** — Auto-format for Clash, Sing-box, Shadowrocket, Hiddify
- 🍎 **HAPP iOS routing** — separate iOS split-tunneling profile with cache isolation from default HAPP routing
- 🔄 **Backup/Restore** — Automatic backups with S3 support
- 💻 **SSH Terminal** — Direct node access from browser
- 🔑 **API Keys** — Secure external access with scopes, IP allowlist, rate limiting
- 🪝 **Webhooks** — Real-time event notifications with HMAC-SHA256 signing
- 🗺 **Network Map** — Visual cascade topology with Forward/Reverse chain routing *(beta)*
- 🌉 **MultiBridge Reverse** — multiple reverse links can share one bridge; the Xray bridge config combines all active links and isolates internal domains by link id
- 🤖 **MCP Integration** — Native AI assistant support (Claude, Cursor, etc.) for panel management

---

## ⚠️ Beta Features

### Network Map & Cascade Topology

> **Status:** beta — fully functional, but manual verification after deploy is recommended.

Cascade topology allows building server chains where clients connect to one node while traffic exits through another. This is useful in scenarios where the entry point must reside in a specific network or jurisdiction — for example, when connections must originate from local cloud provider IP ranges.

#### Why Use This

Many corporate and carrier networks apply IP-range filtering. Traffic to well-known local hosting providers may pass unrestricted, while connections to foreign IPs are blocked or throttled. Cascade topology solves this: clients connect to a server in a "trusted" IP range, and traffic is transparently proxied to an external server.

#### Xray Mechanisms Used

The panel generates Xray-core configurations using the following mechanisms:

| Mechanism | Purpose |
|-----------|---------|
| **Reverse Proxy** | Xray bridge/portal — allows a server behind NAT to initiate a connection to a public node and receive traffic through it |
| **Outbound Chaining** | Sequential proxying through multiple outbounds via `proxySettings.tag` |
| **REALITY** | TLS handshake camouflage to look like a connection to a legitimate site; no domain or certificate required |
| **Transport Layer Proxy** | `transportLayer: true` mode for correct REALITY application in hop chains |

#### Link Modes

**Reverse Proxy** — classic Xray reverse scheme. The Bridge server (typically abroad) initiates a persistent connection to the Portal server. Clients connect to Portal, traffic exits through Bridge.

```
Client ──▶ Portal (entry) ◀── tunnel ── Bridge (exit) ──▶ Internet
                           (bridge initiates connection)
```

- Portal can be behind NAT or firewall — no incoming connections required
- Suitable for scenarios where the entry point must be in a specific network

**Forward Chain** — direct outbound chain. Portal establishes connections through relay nodes to the exit Bridge.

```
Client ──▶ Portal ──▶ Relay (opt.) ──▶ Bridge (exit) ──▶ Internet
           (chained outbounds)
```

- All nodes in the chain must have a public IP
- REALITY is supported on each hop to encrypt inter-server traffic

#### REALITY Between Nodes

Tunnel-REALITY is configured **independently** from the client-facing REALITY on the Portal node. This enables:

- Encrypting inter-server traffic without drawing attention
- Using different SNI/destination for clients vs. tunnels
- Auto-generating x25519 keys and shortIds when creating links

#### Post-Deploy Recommendations

1. Check hop statuses on the Network Map
2. Verify traffic exits through the expected Bridge (check exit IP)
3. For Forward Chain — confirm each relay is reachable on its `tunnelPort`

#### Limitations

| Constraint | Reason |
|------------|--------|
| REALITY + WebSocket | WebSocket doesn't support uTLS fingerprint required by REALITY |
| Forward Chain without public IP | Each hop must accept incoming connections |
| Mixed modes in one chain | Reverse and Forward use different Xray mechanisms and cannot be combined |
| Same port on relay for two hops | A relay that is both bridge and portal requires different ports for incoming and outgoing tunnels |

---

## 🏗 Architecture

```
                              ┌─────────────────┐
                              │     CLIENTS     │
                              │ Clash, Sing-box │
                              │   Shadowrocket  │
                              └────────┬────────┘
                                       │
                     hysteria2:// or vless://
                                       │
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                        ▼
     ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
     │  Hysteria Node  │      │   Xray Node     │      │  Hysteria Node  │
     │   :443 + hop    │      │  VLESS Reality  │      │   :443 + hop    │
     └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
              │                        │                        │
              │    POST /api/auth      │   CC Agent API         │
              │    GET /online         │                        │
              └────────────────────────┼────────────────────────┘
                                       ▼
                          ┌────────────────────────┐
                          │    HYSTERIA PANEL      │
                          │                        │
                          │  • Web UI (/panel)     │
                          │  • HTTP Auth API       │
                          │  • Subscriptions       │
                          │  • SSH Terminal        │
                          │  • Stats Collector     │
                          └───────────┬────────────┘
                                      │
                                      ▼
                          ┌────────────────────────┐
                          │       MongoDB          │
                          └────────────────────────┘
```

### How Authentication Works

**Hysteria:**
1. Client connects to node with `userId:password`
2. Node sends `POST /api/auth` to panel
3. Panel validates user and returns `{ "ok": true/false }`

**Xray:**
1. Client connects with UUID (xrayUuid)
2. CC Agent on node manages user list via API
3. Panel syncs users to node without restarting Xray

### Server Groups

Instead of rigid "plans", use flexible groups:
- Create group (e.g., "Europe", "Premium")
- Assign nodes to group
- Assign users to group
- User gets only nodes from their groups in subscription

---

## 🔧 Node Types

### Hysteria 2

Fast UDP protocol based on QUIC with port hopping and obfuscation support.

**Advantages:**
- High speed on unstable networks
- Port hopping to bypass blocks
- Salamander and Gecko obfuscation (Gecko requires Hysteria 2.9.x)

**Settings:**
- Port, port range for hopping
- ACME or self-signed certificates
- Obfs (`salamander` or `gecko`) with password

**Advanced Hysteria settings in panel:**
- Port Hopping interval (`hopInterval`)
- ACME advanced options (challenge type, alt ports, DNS challenge provider and config)
- Masquerade modes: `proxy` and `string`
- Bandwidth limits (`up` / `down`) and `ignoreClientBandwidth`
- Built-in `speedTest`, `disableUDP`, `udpIdleTimeout`
- Protocol sniffing (`sniff`) and QUIC parameters (`quic`)
- Custom DNS resolver (`resolver`)
- ACL source mode (`inline` or `file`) + GeoIP/GeoSite paths
- Advanced sections are optional and omitted from generated config until enabled in UI

### Xray VLESS

Modern protocol with Reality support and various transports.

**Advantages:**
- Reality — disguise as legitimate HTTPS traffic
- Multiple transports (TCP, WebSocket, gRPC, XHTTP)
- No domain required for Reality

**Transports:**

| Transport | Description | Client Support |
|-----------|-------------|----------------|
| TCP | Direct connection, max speed | All clients |
| WebSocket | Works through CDN and proxies | All clients |
| gRPC | Multiplexing, good for CDN | All clients |
| XHTTP | New splithttp transport | Limited* |

*XHTTP is not supported by all clients (Clash/Sing-box don't support it yet)

**Security:**

| Mode | Description |
|------|-------------|
| Reality | Disguise as popular site, no domain needed |
| TLS | Classic TLS with certificate |
| None | No encryption (not recommended) |

---

## 🚀 Xray Node Setup

### Automatic Setup (Recommended)

1. Add node in panel:
   - Type: **Xray**
   - IP, SSH credentials
   - Security: Reality (recommended)
   - Transport: TCP (recommended for Reality)

2. Click "⚙️ Auto Setup"

3. Panel will automatically:
   - Install Xray-core
   - Generate Reality keys (x25519)
   - Upload config
   - Install CC Agent for user management
   - Open firewall ports
   - Start services

### Reality Settings

| Field | Description | Example |
|-------|-------------|---------|
| Dest | Disguise destination (domain:port) | `www.google.com:443` |
| SNI | Server Name Indication | `www.google.com` |
| Private Key | x25519 private key | Auto-generated |
| Public Key | Public key (for clients) | Auto-generated |
| Short IDs | Session identifiers | Auto-generated |

### CC Agent

CC Agent is a lightweight HTTP service on the node for managing Xray users without restart.

**Features:**
- Add/remove users on the fly
- Traffic stats collection
- Health check

Agent is installed automatically during Xray node auto-setup.

Auto-setup downloads `cc-agent` from this custom repository's GitHub Releases (`YLeon2007/celerity-panel-custom`). The custom agent stays upstream-compatible for `/stats`, `/sync`, `/users`, and `/restart`, and additionally exposes `GET /online` with log-derived per-user VPN state:

- `online=true` appears as soon as Xray logs `accepted ... email: <userId>`;
- users turn offline after 45 seconds without new accepted events;
- the panel polls live state every 15 seconds and falls back to traffic-delta detection only when an old agent has no `/online` endpoint.

---

## 🔧 Hysteria Node Setup

### Understanding Node Configuration

#### Ports
- **Main port (443)** — Port Hysteria listens on
- **Port hopping range (20000-50000)** — UDP ports for hopping
- **Stats port (9999)** — Internal port for stats collection

#### Domain vs SNI

| Field | Purpose | Example |
|-------|---------|---------|
| **Domain** | For ACME/Let's Encrypt certificates | `de1.example.com` → `1.2.3.4` |
| **SNI** | For masquerading (domain fronting) | `www.google.com` |

**Scenarios:**
1. **Simple setup**: Set domain, leave SNI empty
2. **Domain fronting**: Set domain for certs, SNI as popular domain
3. **No domain**: Leave empty — self-signed certificate will be used

### Automatic Setup (Recommended)

1. Add node in panel (IP, SSH credentials)
2. Click "⚙️ Auto Setup"
3. Panel will automatically:
   - Install Hysteria 2
   - Configure ACME or self-signed certificates
   - Set up port hopping
   - Open firewall ports
   - Start service

### Obfuscation (Salamander / Gecko)

Hysteria supports obfuscation to disguise traffic:

1. Enable **Obfs** in node settings
2. Select **Salamander** or **Gecko** (`gecko` requires Hysteria 2.9.x)
3. Set **obfuscation password**
4. Save and update config

Clients will automatically receive the selected `obfs` type and password in subscription.

### Single VPS Setup (Panel + Node)

You can run panel and node on the same VPS (panel TCP, node UDP on 443).

**Option 1: Use panel domain (recommended)**
- Set node domain same as panel domain
- Panel certificates will be copied automatically

**Option 2: No domain (self-signed)**
- Leave domain field empty
- Self-signed certificate will be generated

---

## 📖 API Reference

### API Key Authentication

All `/api/*` endpoints (except `/api/auth` and `/api/files`) require authentication.

**Create a key:** Settings → Security → API Keys → Create Key

**Usage:**
```http
# Option 1 — header
X-API-Key: ck_your_key_here

# Option 2 — Bearer token
Authorization: Bearer ck_your_key_here
```

#### Scopes

| Scope | Access |
|-------|--------|
| `users:read` | Read users |
| `users:write` | Create / update / delete users |
| `nodes:read` | Read nodes |
| `nodes:write` | Create / update / delete / sync nodes |
| `stats:read` | Read stats and groups |
| `sync:write` | Trigger sync, kick users |

#### Rate Limiting

Each key has a configurable rate limit (default: 60 req/min).  
Exceeded requests return `429` with `X-RateLimit-Limit` / `X-RateLimit-Remaining` headers.

---

### Authentication (for nodes)

#### POST `/api/auth`

Validates user on Hysteria node connection.

```json
// Request
{ "addr": "1.2.3.4:12345", "auth": "userId:password" }

// Response (success)
{ "ok": true, "id": "userId" }

// Response (error)
{ "ok": false }
```

### Subscriptions

#### GET `/api/files/:token`

Universal subscription endpoint. Auto-detects format by User-Agent.

| User-Agent | Format |
|------------|--------|
| `shadowrocket` | Base64 URI list |
| `clash`, `stash`, `surge` | Clash YAML |
| `hiddify`, `sing-box`, `karing` | Sing-box JSON |
| Browser | HTML page with QR code |
| Other | Plain URI list |

**Query params:** `?format=clash`, `?format=singbox`, `?format=uri`

#### GET `/api/files/info/:token`

Subscription info (status, traffic, expiry).

### Users

Required scope: `users:read` (GET) / `users:write` (POST, PUT, DELETE)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users` | List users (pagination, filtering, sorting) |
| GET | `/api/users/:userId` | Get user |
| POST | `/api/users` | Create user |
| PUT | `/api/users/:userId` | Update user |
| DELETE | `/api/users/:userId` | Delete user |
| POST | `/api/users/bulk-delete` | Delete selected users (best-effort) |
| POST | `/api/users/:userId/enable` | Enable user |
| POST | `/api/users/:userId/disable` | Disable user |
| POST | `/api/users/:userId/groups` | Add user to groups |
| DELETE | `/api/users/:userId/groups/:groupId` | Remove user from group |
| POST | `/api/users/sync-from-main` | Sync from external DB |

### Nodes

Required scope: `nodes:read` (GET) / `nodes:write` (POST, PUT, DELETE)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/nodes` | List nodes |
| GET | `/api/nodes/:id` | Get node |
| POST | `/api/nodes` | Create node |
| PUT | `/api/nodes/:id` | Update node |
| DELETE | `/api/nodes/:id` | Delete node |
| GET | `/api/nodes/:id/config` | Get node config (YAML/JSON) |
| GET | `/api/nodes/:id/status` | Get node status |
| POST | `/api/nodes/:id/reset-status` | Reset status to online |
| GET | `/api/nodes/:id/users` | Get users on node |
| POST | `/api/nodes/:id/sync` | Sync specific node |
| POST | `/api/nodes/:id/update-config` | Push config via SSH |
| POST | `/api/nodes/:id/setup` | Auto-setup node via SSH |
| POST | `/api/nodes/:id/setup-port-hopping` | Setup port hopping |
| POST | `/api/nodes/:id/groups` | Add node to groups |
| DELETE | `/api/nodes/:id/groups/:groupId` | Remove from group |
| GET | `/api/nodes/:id/agent-info` | Get CC Agent info (Xray) |

### Stats & Sync

| Method | Endpoint | Scope | Description |
|--------|----------|-------|-------------|
| GET | `/api/stats` | `stats:read` | Panel statistics |
| GET | `/api/groups` | `stats:read` | List server groups |
| POST | `/api/sync` | `sync:write` | Sync all nodes |
| POST | `/api/kick/:userId` | `sync:write` | Kick user from all nodes |

---

## 🪝 Webhooks

Send real-time event notifications to any HTTP endpoint.

**Configure:** Settings → Security → Webhooks

### Request Format

```http
POST https://your-endpoint.com/webhook
Content-Type: application/json
X-Webhook-Event: user.created
X-Webhook-Timestamp: 1700000000
X-Webhook-Signature: sha256=<hmac>
User-Agent: C3-Celerity-Webhook/1.0

{
  "event": "user.created",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "data": { ... }
}
```

### Signature Verification

```js
const crypto = require('crypto');
const expected = 'sha256=' + crypto
  .createHmac('sha256', YOUR_SECRET)
  .update(`${timestamp}.${rawBody}`)
  .digest('hex');
// compare with X-Webhook-Signature header
```

### Events

| Event | Trigger |
|-------|---------|
| `user.created` | User created |
| `user.updated` | User updated |
| `user.deleted` | User deleted |
| `user.enabled` | User enabled |
| `user.disabled` | User disabled |
| `user.traffic_exceeded` | User traffic limit reached |
| `user.expired` | User subscription expired |
| `node.online` | Node came online |
| `node.offline` | Node went offline |
| `node.error` | Node error |
| `host.disk_low` | Panel host free disk dropped below the warning threshold |
| `host.disk_critical` | Panel host free disk dropped below the critical threshold |
| `host.disk_recovered` | Panel host free disk recovered above the warning threshold |
| `sync.completed` | Sync cycle finished |

Disk alert thresholds are configured under **Settings → Security → Webhooks**
(`Warning: free space below %` and `Critical: free space below GB`). Alerts fire
once per threshold crossing with hysteresis to avoid spam, and a recovery event
is sent once free space climbs back above the warning level.

---

## 🧹 Disk Space & Maintenance

MongoDB and the panel stop working when the host runs out of disk, so keep an
eye on free space (the dashboard shows a **Disk** chart and webhooks can alert
you — see above). The most common cause of a full disk is Docker accumulating
unused images, containers and logs over time.

**Cap container log size** (prevents logs from filling the disk). Add to each
service in your `docker-compose.yml`:

```yaml
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
```

**Periodically reclaim space** used by dangling/unused Docker data:

```bash
# Safe: remove only dangling images and build cache
docker image prune -f
docker builder prune -f

# Aggressive: also removes ALL unused images (next deploy re-pulls them)
docker system prune -a -f
```

A weekly `cron` job running `docker image prune -f` is usually enough to keep
disk usage in check.

---

## 📊 Data Models

### User

| Field | Type | Description |
|-------|------|-------------|
| `userId` | String | Unique ID |
| `username` | String | Display name |
| `subscriptionToken` | String | URL token for subscription |
| `xrayUuid` | String | UUID for Xray VLESS (auto-generated) |
| `enabled` | Boolean | User active status |
| `groups` | [ObjectId] | Server groups |
| `nodes` | [ObjectId] | Direct node assignments |
| `traffic` | Object | `{ tx, rx, lastUpdate }` — used traffic |
| `trafficLimit` | Number | Traffic limit in bytes (0 = unlimited) |
| `maxDevices` | Number | Device limit (0 = group limit, -1 = unlimited) |
| `expireAt` | Date | Expiration date |

### Node

| Field | Type | Description |
|-------|------|-------------|
| `type` | String | `hysteria` or `xray` |
| `name` | String | Display name |
| `flag` | String | Country flag (emoji) |
| `ip` | String | IP address |
| `domain` | String | Domain for SNI/ACME |
| `sni` | String | Custom SNI for masquerading |
| `port` | Number | Main port (443) |
| `portRange` | String | Port hopping range |
| `portConfigs` | Array | Multi-port: `[{ name, port, portRange, enabled }]` |
| `obfs` | Object | Obfuscation: `{ type: 'salamander' \| 'gecko', password }` |
| `statsPort` | Number | Hysteria stats port (9999) |
| `statsSecret` | String | Stats API secret |
| `groups` | [ObjectId] | Server groups |
| `outbounds` | Array | Proxies for ACL: `[{ name, type, addr }]` |
| `aclRules` | [String] | ACL rules |
| `maxOnlineUsers` | Number | Max online for load balancing |
| `rankingCoefficient` | Number | Sorting coefficient (1.0) |
| `status` | String | online/offline/error/syncing |
| `traffic` | Object | `{ tx, rx, lastUpdate }` — node traffic |
| `xray` | Object | Xray settings (see below) |

#### Xray Settings (node.xray)

| Field | Type | Description |
|-------|------|-------------|
| `transport` | String | tcp, ws, grpc, xhttp |
| `security` | String | reality, tls, none |
| `flow` | String | xtls-rprx-vision (for tcp) |
| `fingerprint` | String | chrome, firefox, safari, etc. |
| `alpn` | [String] | ALPN protocols (h3, h2, http/1.1) |
| `realityDest` | String | Disguise destination |
| `realitySni` | [String] | Server names |
| `realityPrivateKey` | String | x25519 private key |
| `realityPublicKey` | String | Public key |
| `realityShortIds` | [String] | Short IDs |
| `realitySpiderX` | String | Spider X path — start URL for the REALITY spider on probe (empty by default; per-node value recommended) |
| `wsPath` | String | WebSocket path |
| `wsHost` | String | WebSocket host header |
| `grpcServiceName` | String | gRPC service name |
| `xhttpPath` | String | XHTTP path |
| `xhttpHost` | String | XHTTP host header |
| `xhttpMode` | String | auto, packet-up, stream-up |
| `apiPort` | Number | Xray gRPC API port (61000) |
| `inboundTag` | String | Inbound tag (vless-in) |
| `agentPort` | Number | CC Agent port (62080) |
| `agentToken` | String | Agent token |
| `agentTls` | Boolean | TLS for CC Agent |

### ServerGroup

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | Group name |
| `description` | String | Description |
| `color` | String | UI color (#hex) |
| `maxDevices` | Number | Device limit for group |
| `subscriptionTitle` | String | Title in subscription profile |

---

## 🚫 Traffic Filtering (ACL)

Control traffic routing on each Hysteria node. Access: **Panel → Node → Traffic Filtering**.

### Built-in Actions

| Action | Description |
|--------|-------------|
| `reject(...)` | Block connection |
| `direct(...)` | Allow through server |

### Rule Examples

```
reject(suffix:doubleclick.net)     # Block ads
reject(suffix:googlesyndication.com)
reject(geoip:cn)                   # Block Chinese IPs
reject(geoip:private)              # Block private IPs
direct(all)                        # Allow everything else
```

### Custom Proxy Routing

1. Add proxy (e.g., `my-proxy`, SOCKS5, `1.2.3.4:1080`)
2. Use in rules: `my-proxy(geoip:ru)`

---

## ⚖️ Load Balancing

Configure in **Settings**:

- **Enable balancing** — Sort nodes by current load
- **Hide overloaded** — Exclude nodes at capacity

Algorithm:
1. Get user's nodes from groups
2. Sort by load % (online/max)
3. Filter overloaded if enabled
4. Fall back to `rankingCoefficient`

---

## 🔒 Device Limits

**Priority:**
1. User's personal limit (`maxDevices > 0`)
2. Minimum limit from user's groups
3. `-1` = unlimited

**Device Grace Period** — delay (in seconds) before counting a disconnected device, to avoid false triggers during reconnections.

---

## 📱 Subscription Page Customization

Customize the HTML subscription page in **Settings → Subscription**:

| Field | Description |
|-------|-------------|
| `Logo URL` | Logo URL for page header |
| `Page Title` | Page title |
| `Support URL` | Support link (button at bottom) |
| `Web Page URL` | Profile URL (`profile-web-page-url` header) |

The subscription page automatically shows:
- QR code for app import
- Traffic stats and expiration
- Location list with copy buttons

---

## 💾 Backups

### Auto Backups

Configure in **Settings → Backups**:
- Interval (in hours)
- Number of local copies to keep

### Manual Backup

Dashboard button — file auto-downloads.

### Restore

Upload `.tar.gz` archive via interface.

### S3-Compatible Storage

Backups can be automatically uploaded to S3-compatible storage (AWS S3, MinIO, Backblaze B2, Cloudflare R2, etc.).

**Configure:** Settings → Backups → S3

| Field | Description |
|-------|-------------|
| `Endpoint` | Storage URL (for MinIO, etc.). Leave empty for AWS S3 |
| `Region` | Region (e.g., `us-east-1`) |
| `Bucket` | Bucket name |
| `Prefix` | Prefix/folder for backups |
| `Access Key ID` | Access key |
| `Secret Access Key` | Secret key |
| `Keep Last` | How many backups to keep in S3 |

**Configuration examples:**

```env
# AWS S3
Endpoint: (empty)
Region: eu-central-1
Bucket: my-backups

# MinIO
Endpoint: https://minio.example.com
Region: us-east-1
Bucket: backups

# Cloudflare R2
Endpoint: https://<account-id>.r2.cloudflarestorage.com
Region: auto
Bucket: my-backups
```

---

## 🐳 Docker Compose

This custom repository is intended to run from source. The production compose file builds the backend locally from the current checkout:

```bash
docker compose -f docker-compose.yml up -d --build
```

Use the one-command installer when possible; it writes `.env`, prepares directories, and runs the compose command for you.

Do **not** replace the backend with `clickdevtech/hysteria-panel:latest` unless you intentionally want the upstream image without this repository's custom commits.

---

## 📝 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PANEL_DOMAIN` | ✅ | Panel domain |
| `DOKPLOY_PANEL_HOST` | ❌ | Traefik host for Dokploy (`Host(...)` rule) |
| `DOKPLOY_TRAEFIK_SERVICE_PORT` | ❌ | Traefik/backend service port in Dokploy (default: `3000`) |
| `ACME_EMAIL` | ✅ | Let's Encrypt email |
| `ENCRYPTION_KEY` | ✅ | SSH encryption key (32 chars) |
| `SESSION_SECRET` | ✅ | Session secret |
| `MONGO_PASSWORD` | ✅ | MongoDB password (for Docker) |
| `MONGO_USER` | ❌ | MongoDB user (default: hysteria) |
| `MONGO_URI` | ❌ | MongoDB connection URI (for non-Docker) |
| `REDIS_URL` | ❌ | Redis URL for cache (default: in-memory) |
| `USE_CADDY` | ❌ | Serve plain HTTP on `PORT` behind a reverse proxy instead of Greenlock HTTPS. Used by `docker-compose.yml`/`docker-compose.dokploy.yml`. Unset = standalone HTTPS via Greenlock (needs a real domain + public ports 80/443) |
| `PORT` | ❌ | Backend HTTP port when `USE_CADDY=true` (default: `3000`) |
| `PANEL_IP_WHITELIST` | ❌ | IP whitelist for panel |
| `SYNC_INTERVAL` | ❌ | Sync interval in minutes (default: 2) |
| `API_DOCS_ENABLED` | ❌ | Enable interactive API docs at `/api/docs` |
| `LOG_LEVEL` | ❌ | Logging level (default: info) |

---

## 🤝 Contributing

Pull requests welcome!

---

## 📄 License

MIT
