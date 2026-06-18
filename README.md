# wazuh-slack

Rust connector that pipes Slack activity into Wazuh as a custom source. Fills the gap left by Wazuh's stock wodles, which cover Office365, GitHub, AWS, Azure, GCP — but not Slack.

Designed primarily for **abnormal user-behaviour detection** (insider scenarios like the 2024 Replit case), with Wazuh's stateful frequency rules doing the correlation.

---

## Architecture

```
Slack (Events / Audit / Web)
        │
        ▼
  ┌──────────────┐    ┌───────────┐    ┌───────────┐
  │  Sources     │ ─► │ Normalizer│ ─► │  Filter   │
  │ (async tasks)│    └───────────┘    └─────┬─────┘
  └──────────────┘                            ▼
                                       bounded mpsc
                                            │
                                            ▼
                                       ┌─────────┐
                                       │  Sink   │ ─► Wazuh analysisd
                                       └─────────┘
```

Pluggable sinks: `UnixSocketSink` (manager-side, native protocol; reconnects if
analysisd restarts and auto-replays its spool), `JsonFileSink` (agent-side via
`localfile`), `StdoutSink` (dev). Sources that die (e.g. the Socket Mode
listener dropping) are restarted by the supervisor with exponential backoff.

---

## Tier capability matrix

| Detection | Free | Pro/Business+ | Enterprise Grid |
|---|---|---|---|
| Channel-join burst | ✅ Events API | ✅ | ✅ |
| File-share / public-link burst | ✅ Events API | ✅ | ✅ |
| Off-hours DM activity | ✅ Events API | ✅ | ✅ |
| App install/uninstall, tokens revoked | ✅ Events API | ✅ | ✅ |
| Login-failure brute force | ❌ | ✅ `team.accessLogs` | ✅ Audit Logs |
| **File-download burst (Replit pattern)** | ❌ | ❌ | ✅ Audit Logs `file_downloaded` |
| MFA / SSO disabled | ❌ | ❌ | ✅ Audit Logs |
| Admin role grant | ❌ | ❌ | ✅ Audit Logs |
| Search-query volume | ❌ | ❌ | ⚠️ Discovery API (DLP approval only) |

Connector probes the workspace tier at startup, disables unsupported sources, logs warnings.

---

## Quickstart (dev, no Wazuh)

```powershell
# 1. provide Slack tokens (set in the process env — the raw binary does NOT
#    read .env; only docker-compose auto-loads .env)
$env:SLACK_BOT_TOKEN  = "xoxb-..."   # bot token
$env:SLACK_APP_TOKEN  = "xapp-..."   # app-level token (Socket Mode)
$env:SLACK_USER_TOKEN = "xoxp-..."   # user token, Enterprise Grid only — required for the audit source

# 2. enable events source in config/wazuh-slack.dev.yaml
#    (events.enabled: true); for Enterprise Grid also set audit.enabled: true
#    plus token_user + org_id

# 3. run with JsonFileSink → events.ndjson
cargo run --release -- --config config/wazuh-slack.dev.yaml
```

> The audit source needs a **distinct `xoxp-` user token** — reusing the `xoxb-`
> bot value makes the startup probe report `audit_logs: false` and the source is
> skipped.

Generate test signal: join channels / share files in the Slack workspace. Watch `events.ndjson` populate.

## Quickstart (full Wazuh stack via docker-compose)

Brings up the full Wazuh stack (**manager + indexer + dashboard**) plus the
connector. The connector writes NDJSON into a shared volume; the manager tails
it via `<localfile>` and runs the custom Slack rules/decoder.

### Components

Wazuh is three separate services — the manager alone has **no web UI**:

| Service | Job |
|---|---|
| `wazuh.manager` | analysisd, decoders, rules → writes `alerts.json` |
| `wazuh.indexer` | OpenSearch fork — stores/searches alerts |
| `wazuh.dashboard` | Kibana fork — web UI (reads from the indexer) |

### Files

| File | Job |
|---|---|
| `docker-compose.yml` | 4 services: manager + indexer + dashboard + connector |
| `generate-certs.yml` | one-shot TLS cert generator |
| `config/certs.yml` | cert node definitions |
| `config/wazuh_indexer/*.yml` | indexer config + demo internal users |
| `config/wazuh_dashboard/*.yml` | dashboard config |
| `config/wazuh_cluster/wazuh_manager.conf` | full `ossec.conf` with the Slack `<localfile>` block baked in |
| `config/wazuh-slack.docker.yaml` | connector config (events source on, `json_file` sink → shared volume) |
| `Dockerfile` / `.env.example` | connector image + token template |

### Run (2 steps)

```powershell
# 1. generate TLS certs ONCE (writes to config/wazuh_indexer_ssl_certs/)
docker compose -f generate-certs.yml run --rm generator

# 2. provide tokens, then launch
copy .env.example .env        # edit .env with real xoxb-/xapp- tokens
docker compose up --build -d
```

### Access

- **Dashboard UI:** `https://localhost` — login `admin` / `SecretPassword`
- **Alerts (file):** `docker compose exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.json`

### Windows Server / WSL2 caveats

| Roadblock | Fix |
|---|---|
| Indexer needs `vm.max_map_count` | run **before** up: `wsl -d docker-desktop sysctl -w vm.max_map_count=262144` (else indexer crash-loops) |
| RAM | indexer JVM is `-Xms1g -Xmx1g`; give WSL2 ≥ 4 GB in `.wslconfig` |
| CRLF line endings | `.gitattributes` pins all mounted config files to LF (CRLF makes the dashboard auth to the indexer with `kibanaserver\r` → "unable to connect to the indexer"). If files were checked out CRLF before the pin, run `git checkout -- .` after pulling |
| Cert filenames | the generator emits `wazuh.manager.pem`, `wazuh.indexer.pem`, etc.; compose mounts expect exactly those — don't rename |
| First boot slow | indexer security-index init takes ~1–2 min; dashboard returns 503 until the indexer is green |
| Default passwords | `SecretPassword` / `kibanaserver` are demo-only — change before any non-PoC use |

> **Lighter alternative:** for a pipeline-only PoC you can drop the indexer +
> dashboard and run the manager alone, reading alerts from `alerts.json`. The
> manager is sufficient to decode events, run rules, and fire alerts.

### Manager-side native socket (alternative to the file sink)

On a Linux host where the connector runs **on the manager box**, skip the file
sink and write straight to analysisd:

```bash
cargo build --release   # requires /var/ossec/queue/sockets writable, run as wazuh user
SLACK_BOT_TOKEN=xoxb-... SLACK_APP_TOKEN=xapp-... \
  ./target/release/wazuh-slack --config config/wazuh-slack.example.yaml   # sink.kind: unix_socket
```

---

## Slack app manifest (minimum)

Create an app at api.slack.com/apps, install to workspace. Required scopes:

**Bot scopes (`xoxb-`):**
- `channels:history`, `groups:history`, `im:history`, `mpim:history`
- `channels:read`, `groups:read`, `im:read`, `users:read`
- `files:read`

**User scopes (`xoxp-`, Enterprise Grid only):**
- `auditlogs:read` — Audit Logs API. Install the app **org-wide** with **Org Owner** approval; the resulting user token must be **separate from the bot token**.
- `admin` — only if you enable the `access_logs` source (`team.accessLogs`). The installing user must be a Workspace Admin/Owner. The connector sends this **user** token to `team.accessLogs` (Gap 6 fixed).

**Socket Mode app-level token (`xapp-`):**
- `connections:write`

Subscribe to events: `message.channels`, `message.groups`, `message.im`, `file_shared`, `file_public`, `file_deleted`, `channel_created`, `channel_archive`, `member_joined_channel`, `member_left_channel`, `app_installed`, `app_uninstalled`, `tokens_revoked`, `team_join`, `user_change`, `subteam_created`.

**Mark the app as "internal/custom"** (not Marketplace-distributed) to avoid the May 2025 `conversations.history` rate-limit downgrade.

### Known issues

- **`access_logs` source now uses the user token (Gap 6 fixed).** `team.accessLogs`
  needs the `admin` scope on a **user** token (`xoxp-`); the poller and supervisor
  were switched from the bot token, so `access_logs.enabled: true` works with a
  user token carrying `admin`. The Audit Logs API still carries richer login +
  IP/geo data, so this source remains optional.
- **`filters.audit.allow` is still a whitelist — keep it in sync with the rules.**
  The example allow-list passes every action the shipped rules match (including
  `channel_created_external_shared` / `guest_created` for 100074/100075 and the
  insider-threat set `anomaly`, `export_*`, `*_exported`, `user_login`, …), but
  any audit action you add a rule for must also be added here or it is dropped
  before Wazuh (Gap 1).
- **TLS certs are no longer committed.** `config/wazuh_indexer_ssl_certs/` is
  gitignored; a fresh clone must run the cert generator (Quickstart step 1)
  before `docker compose up`.

---

## PoC demo scenarios

`scripts/demo.ps1` injects synthetic `NormalizedEvent` bursts straight into the
Wazuh ingest path (same decoder + rule chain as live traffic), so the stateful
frequency rules fire **without** needing a populated Slack workspace or
Enterprise scopes. Run against the docker stack:

```powershell
# all three scenarios
./scripts/demo.ps1 -Scenario all -Target docker

# or one at a time
./scripts/demo.ps1 -Scenario channel-recon
./scripts/demo.ps1 -Scenario file-exfil
./scripts/demo.ps1 -Scenario replit

# watch the alerts land
docker compose exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.json
```

| Scenario (`-Scenario`) | Burst injected | Wazuh rule that fires |
|---|---|---|
| `channel-recon` | 25× `member_joined_channel`, one actor | `100011` (level 10) |
| `file-exfil` | 25× `file_shared` + 6× `file_public`, one actor | `100021` + `100026` (level 12) |
| `replit` | 55× audit `file_downloaded`, one actor | `100051` (level 12) |
| `anomaly` | 1× audit `anomaly` | `100080` (level 12) |
| `export` | 1× `export_started` + 1× `organization_exported` | `100081` + `100083` (level 12/13) |
| `login-geo` | 1× audit `user_login` from untrusted IP + country | `100091` + `100092` (level 10/8) |
| `off-hours` | 16× audit `file_downloaded` | `100094` (level 12, off-hours window only) |

The `replit` scenario reproduces the headline insider pattern on synthetic
**Enterprise audit** signal — proving the correlation rule works today; on a real
Grid org the only change is the connector sourcing `file_downloaded` from the
Audit Logs API instead of the injector.

Single-event rule check (decoder + base rule, no burst) via `wazuh-logtest`:

```powershell
./scripts/logtest.ps1 -Action member_joined_channel
./scripts/logtest.ps1 -Action file_downloaded -Source audit
```

Live-traffic scenarios (real Slack events, free tier): join channels / share
files / make a file public / revoke a token in the workspace → rules `100011`,
`100021`, `100026`, `100030` fire from genuine Events API traffic.

---

## Observability & ops

| Endpoint | Config key | Purpose |
|---|---|---|
| `GET /metrics` | `observability.prometheus_bind` | Prometheus counters: `wsc_events_received_total{source}`, `wsc_events_filtered_total`, `wsc_events_emitted_total`, `wsc_sink_errors_total` |
| `GET /healthz` | `observability.health_bind` | liveness JSON; `200` healthy, `503` while starting or when poll sources go stale |

`/healthz` body:

```json
{"status":"ok","uptime_s":42,"active_sources":2,"events_emitted":17,"last_emit_age_s":3}
```

`status` is `starting` until sources are wired, `ok` once running, `stale` if
poll-based sources produce nothing for 3× their longest poll interval (floor
300s). Pure push setups (Events API only) never go stale — there is no cadence
to baseline. The docker `wazuh-slack` service wires this to a container
`healthcheck`.

**Cold-start backfill clamp** — `slack.backfill_days` (default `90`) caps how far
back pollers reach on a fresh cursor, matching the Free-tier 90-day data
horizon so a first run doesn't scan permanently-empty history.

**Token rotation** — only relevant if the Slack app has *Token Rotation* enabled
(tokens then expire ~12h). Internal/custom apps use non-expiring tokens and need
nothing here. The config accepts a `slack.rotation` block (`client_id`,
`client_secret`, `refresh_token`, `refresh_seconds`) as forward-looking
scaffolding; it is **parsed but not yet acted on**, and the connector logs a
warning if it is set, so the static tokens remain in use until a refresher is
implemented.

## Layout

```
project-a/
├─ Cargo.toml                    workspace
├─ rust-toolchain.toml           stable + rustfmt + clippy
├─ Dockerfile                    connector image (multi-stage)
├─ docker-compose.yml            full stack: manager + indexer + dashboard + connector
├─ generate-certs.yml            one-shot TLS cert generator
├─ .env.example                  SLACK_BOT_TOKEN / SLACK_APP_TOKEN template
├─ config/
│  ├─ wazuh-slack.dev.yaml       dev profile (JsonFileSink, local paths)
│  ├─ wazuh-slack.docker.yaml    compose profile (JsonFileSink → shared volume)
│  ├─ wazuh-slack.example.yaml   prod shape (UnixSocketSink)
│  ├─ certs.yml                  cert node definitions
│  ├─ wazuh_indexer/             indexer config + internal users
│  ├─ wazuh_dashboard/           dashboard config
│  └─ wazuh_cluster/             manager ossec.conf (Slack localfile baked in)
├─ crates/
│  ├─ slack-connector-core       types, traits, config, filter
│  ├─ slack-sources              EventsSocket, AuditPoller, dedup, state
│  ├─ wazuh-sinks                Stdout, JsonFile, UnixSocket
│  ├─ slack-connector-cli        bin: wazuh-slack
│  └─ slack-connector-test-fixtures   Slack JSON samples
├─ scripts/
│  ├─ demo.ps1                   inject scenario bursts (channel-recon/file-exfil/replit)
│  └─ logtest.ps1                single-event wazuh-logtest check
├─ wazuh-rules/0500-slack-rules.xml
├─ wazuh-decoders/0501-slack-decoder.xml
├─ wazuh-lists/                  CDB allow-lists (trusted networks, allowed countries)
└─ deploy/
   ├─ systemd/wazuh-slack.service
   ├─ ossec.conf.wodle.snippet
   └─ ossec.conf.localfile.snippet
```

---

## Status

| Phase | State |
|---|---|
| 0 — Bootstrap (workspace, config, Stdout/JsonFile sinks, traits) | ✅ |
| 1 — Sources (EventsSocket real impl, AuditPoller, SQLite state, dedup) | ✅ |
| 2 — Filter + normalizer | ✅ |
| 3 — Sinks (UnixSocket with spool, JsonFile rotation) | ✅ |
| 4 — Wazuh rules (≥15) + decoder | ✅ |
| 5 — Observability (Prometheus exporter, tier probe, `/healthz`) | ✅ |
| 6 — E2E docker-compose (full stack) + demo scripts | ✅ |
| 7 — `team.accessLogs` + `WebInventoryPoller` sources | ✅ `WebInventoryPoller` + `team.accessLogs` (user-token fix, Gap 6) |
| 8 — Insider-threat detection gaps 1–6 (anomaly, export, login-geo CDB, off-hours, filter) | ✅ rules 100080–100094, `wazuh-lists/` |

**Live verification (2026-06-09):** events, audit, and web_inventory confirmed
working end-to-end against a real **Enterprise Grid** org (`tier: Enterprise`,
`audit_logs: true`); audit pulled genuine actions on the first poll. Open
follow-ups in `INSIDER-THREAT-GAPS.md`.

---

## License

MIT OR Apache-2.0
