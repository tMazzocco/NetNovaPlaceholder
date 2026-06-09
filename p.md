# Wazuh ↔ Slack Connector — Implementation Plan

**Language:** Rust (stable, async via Tokio)
**Direction:** Slack (source) → Connector → Wazuh (sink)
**Working dir:** `C:\Users\t.mazzocco\Desktop\esgi\m1\project-a` (greenfield)
**Date:** 2026-05-18

---

## 1. Context

Wazuh ships with built-in wodles for O365, GitHub, AWS, Azure, GCP — but **no Slack source connector exists** (community or first-party). Existing `integrations/slack` in Wazuh is the opposite direction (alerts → Slack webhook).

This project fills that gap: a Rust daemon that ingests Slack security/activity telemetry, normalizes it, applies user-defined filters, and delivers it to Wazuh's analysis pipeline so it can be decoded, correlated against rules, and surfaced in the Wazuh dashboard alongside other SIEM data.

**Why Rust:** memory safety + single static binary (easy deploy on Wazuh manager/agent host), strong async ecosystem (Tokio, reqwest, tokio-tungstenite for Socket Mode), no GC pauses for a long-running poller, and contrast with the Python-based stock wodles (lower footprint).

---

## 2. Critical Constraint — Slack Tier

> **Update 2026-06-09 (verified live):** the dev/test workspace is in fact an
> **Enterprise Grid** org (team `T0AN1S601NX`, enterprise `E0AN66GDRRU`), not the
> free workspace originally assumed. The startup tier probe reports
> `tier: Enterprise`, `audit_logs: true`. The Audit Logs API path is therefore
> **validated end-to-end** — a live run pulled real actions (`app_installed`,
> `role_assigned`, `user_channel_join`, `public_channel_created`, `user_created`,
> `org_app_workspace_added`, `org_app_upgraded_to_org_install`). The
> graceful-degradation design below still holds and is now confirmed against a
> real Grid token; Audit Logs is the **primary** source on this org, with Events
> API + Web API as supplements. Open follow-ups tracked in `INSIDER-THREAT-GAPS.md`.

The table below was scoped against the originally-assumed free workspace. It
remains accurate as the cross-tier capability map:

| API surface                  | Free | Pro/Business+ | Enterprise Grid |
|------------------------------|------|---------------|-----------------|
| Web API (users, channels, files, conversations.history) | ✅ | ✅ | ✅ |
| Events API (HTTP + Socket Mode)                        | ✅ | ✅ | ✅ |
| `team.accessLogs` (login history)                       | ❌ (paid only) | ✅ | ✅ |
| **Audit Logs API** (`auditlogs:read`)                  | ❌ | ❌ | ✅ only |
| **Discovery API** (DLP/eDiscovery)                      | ❌ | ❌ | ✅ + approval |
| SCIM                                                    | ❌ | ❌ | ✅ |

**Implication:** on the free dev workspace, only the Web API and the Events API will return data. Audit Logs / Discovery / SCIM / accessLogs code paths must be **implemented behind feature-detection** so the connector gracefully degrades and so a future Enterprise customer can flip them on via config without code changes.

Action items derived from this:
- All source modules behind a trait `LogSource` + runtime registry.
- Startup self-test calls `auth.test` and `admin.*` probe endpoints, logs which sources are usable on the bound token, disables the rest.
- README must state clearly: "Production-grade Slack SIEM coverage requires Enterprise Grid for Audit Logs API. On lower tiers, coverage is limited to Events API + Web API polling."

---

## 3. Slack Side — Collection Design

### 3.1 Sources (in priority order)

1. **Audit Logs API** — `GET https://api.slack.com/audit/v1/logs`
   - Scope: `auditlogs:read` (Org-installed app, Org Owner approval).
   - Tier 3 rate limit (~50 req/min) — **org-wide, shared across all apps**. Must back off on `Retry-After` and persist a "rate-limit-until" timestamp.
   - Cursor pagination, max 9 999 events/page, params `oldest`/`latest`/`action`/`actor`/`entity`.
   - Schema: `{id, date_create, action, actor:{type,user:{...}}, entity:{type,...}, context:{location,ua,ip_address}}`.
   - **Cursor persistence**: store last `date_create` + `id` in SQLite (mirrors `wodles/aws/aws_s3.py` pattern).

2. **Events API — Socket Mode** (preferred over HTTP for this connector)
   - Why Socket Mode: no public ingress required on the Wazuh host. Uses `xapp-` app-level token + outbound WebSocket.
   - Lib: `slack-morphism` v2.19 (Tokio, actively maintained) for events; raw `reqwest` for Audit Logs (no first-class support there).
   - Subscribed events (subset): `message.channels`, `message.groups`, `message.im`, `file_shared`, `file_public`, `file_deleted`, `channel_created`, `channel_archive`, `channel_unarchive`, `member_joined_channel`, `member_left_channel`, `app_installed`, `app_uninstalled`, `tokens_revoked`, `team_join`, `user_change`, `pin_added`, `link_shared`, `subteam_created`.
   - **Dedup required**: Slack retries on missed ACK. Maintain a bounded LRU of `event_id` (~10k entries) keyed in memory + journaled to disk on shutdown.

3. **`team.accessLogs`** — login/IP history. Paid tier. Poll every N minutes, cursor on `date_first`.
   - **Known bug (verified 2026-06-09):** `team.accessLogs` requires the `admin` scope on a **user token (`xoxp-`)**; with a bot token Slack returns `not_allowed_token_type`. The current `AccessLogsPoller` is wired with `token_bot` (`supervisor.rs`), so this source fails until it is switched to `token_user`. Tracked as Gap 6 in `INSIDER-THREAT-GAPS.md`. Lower priority — the Audit Logs API already carries richer login + IP/geo data.

4. **Discovery API** — message content export. Requires Slack-approved DLP app. Out of scope for v1; stub the trait, document the gap.

5. **Web API polling (low-frequency baseline)** — `users.list`, `conversations.list`, `admin.apps.approved.list`, `admin.users.session.list`. Provides inventory snapshots and catches things audit logs miss on lower tiers.

### 3.2 Auth & token handling

- Token types: `xoxb-` (bot, Web API), `xoxp-` (user, required for `auditlogs`), `xapp-` (app-level, Socket Mode).
- **Token rotation enabled** (12h refresh). Store refresh token; persist new access token atomically (write-tmp + rename) — never lose a token mid-rotation. Reject startup if both stored token and refresh token are invalid.
- Secrets storage options in config (in order of preference): OS keyring (via `keyring` crate) → env var → file with `0600` perms. Never log token values; redact in error chains.

### 3.3 Slack-side roadblocks

| Roadblock | Mitigation |
|-----------|-----------|
| Free tier blocks audit logs entirely | Feature-detect, degrade, document |
| Tier-3 audit limit is org-wide | Shared-quota awareness; expose `slack_audit_rate_remaining` metric |
| Events API retry storms (Slack retries 3× on ACK miss) | Sub-3s ACK path independent of sink write; dedup LRU |
| Socket Mode WS disconnects | Auto-reconnect with jitter; resume cursor for any polled sources |
| Message events on huge channels = high volume | Per-source rate limit + per-source filter applied **before** Wazuh write |
| Schema drift (Slack adds fields without notice) | Decode into `serde_json::Value`, only strongly-type fields the filter needs, pass full payload through |
| Free workspace can't simulate audit-log payloads for testing | Bundle fixtures captured from Slack's documented examples; integration tests run against fixtures, not live |

---

## 4. Wazuh Side — Ingestion Design

### 4.1 Reviewed options

| Method | Verdict |
|--------|---------|
| Wazuh REST API (port 55000) | ❌ — mgmt only, no log ingest endpoint |
| Syslog to remoted (514/1514) | ⚠️ — works but loses JSON structure unless tuned |
| Write to analysisd UNIX socket `/var/ossec/queue/sockets/queue` | ✅ — **idiomatic**; what every stock wodle does |
| File + `<localfile log_format="json">` on a Wazuh agent | ✅ — easiest deploy; no manager access needed |
| Embed as library inside Wazuh | ❌ — Wazuh is C, no stable plugin ABI |

### 4.2 Decision — **Pluggable sink backend** (user undecided on deploy target)

Define trait:

```rust
#[async_trait]
trait WazuhSink: Send + Sync {
    async fn emit(&self, event: NormalizedEvent) -> Result<()>;
    async fn flush(&self) -> Result<()>;
}
```

Implementations shipped:

- **`UnixSocketSink`** (Linux only, manager-side install)
  - Path: `/var/ossec/queue/sockets/queue` (configurable).
  - Protocol: `AF_UNIX SOCK_DGRAM`. Wire format: `1:slack-<source>:<json>` where `1` = locally-collected queue byte and `slack-<source>` is the synthetic location (e.g. `slack-audit`, `slack-events`).
  - Handle `EAGAIN` (analysisd queue full): retry with exponential backoff up to N attempts, then spool to disk (`./spool/*.ndjson`) and replay on recovery.

- **`JsonFileSink`** (cross-platform, agent-side install)
  - Writes NDJSON to a rotated file (`logrotate`-compatible). Wazuh agent config:
    ```xml
    <localfile>
      <log_format>json</log_format>
      <location>/var/log/wazuh-slack/events.ndjson</location>
    </localfile>
    ```

- **`StdoutSink`** (dev only, for `cargo run` testing).

User picks via YAML:

```yaml
sink:
  kind: unix_socket   # or: json_file | stdout
  unix_socket:
    path: /var/ossec/queue/sockets/queue
  json_file:
    path: /var/log/wazuh-slack/events.ndjson
    rotate_mb: 100
```

### 4.3 Wazuh-side artifacts shipped alongside the binary

- `wazuh-rules/0500-slack-rules.xml` — custom rules (IDs ≥ 100000), grouped `<group name="slack,authentication,...">`. Examples: failed login burst, token revoked, external user added, app installed by non-admin, file made public.
- `wazuh-decoders/0501-slack-decoder.xml` — minimal; JSON decoder handles most, this just sets `program_name` and groups based on `event.action` prefix.
- `ossec.conf` snippet for `<wodle name="command">` invocation (manager-side) and `<localfile>` block (agent-side).

### 4.4 Wazuh-side roadblocks

| Roadblock | Mitigation |
|-----------|-----------|
| analysisd socket backpressure | Bounded mpsc channel + disk spool + metric |
| Wazuh upgrade renaming socket path | Path is config-driven, not hardcoded |
| Decoder field-name collisions with other modules | Namespace all fields under `slack.*` in normalized output |
| Permissions: only `wazuh` user can write to socket | Document `setcap` / running connector as `wazuh` user |
| No Wazuh on Windows manager (only agent) | UnixSocketSink is Linux-only; on Windows ship `JsonFileSink` + agent localfile |

---

## 5. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     wazuh-slack-connector (Rust)                    │
│                                                                     │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐             │
│  │ AuditPoller  │   │ EventsSocket │   │ AccessPoller │  ← Sources  │
│  │  (reqwest)   │   │(slack-morph.)│   │  (reqwest)   │   (traits)  │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘             │
│         │                  │                  │                     │
│         └──────────────────┴──────────────────┘                     │
│                            │                                        │
│                    raw `serde_json::Value`                          │
│                            ▼                                        │
│                  ┌──────────────────┐                               │
│                  │  Normalizer      │  ECS-ish flatten,             │
│                  │  (slack→common)  │  add @timestamp, slack.*      │
│                  └────────┬─────────┘                               │
│                           ▼                                         │
│                  ┌──────────────────┐                               │
│                  │  FilterEngine    │  YAML allow/deny rules        │
│                  │ (action, actor,  │  evaluated against event      │
│                  │ channel, regex)  │                               │
│                  └────────┬─────────┘                               │
│                           ▼                                         │
│            bounded mpsc<NormalizedEvent> (cap = 10k)                │
│                           ▼                                         │
│                  ┌──────────────────┐                               │
│                  │  Sink dispatcher │ ── retry, spool, metrics      │
│                  └────────┬─────────┘                               │
│                           ▼                                         │
│         ┌─────────────────┼──────────────────┐                      │
│         ▼                 ▼                  ▼                      │
│   UnixSocketSink     JsonFileSink       StdoutSink                  │
│         │                 │                                         │
│         ▼                 ▼                                         │
│   /var/ossec/...   /var/log/wazuh-slack/events.ndjson               │
│         │                 │                                         │
│         └────► Wazuh analysisd ◄──── (via localfile or direct)      │
│                                                                     │
│  Side-cars:                                                         │
│   • SQLite state (cursors, dedup LRU, token cache)                  │
│   • Prometheus /metrics endpoint (port 9183)                        │
│   • /healthz endpoint                                               │
│   • Structured logs (tracing crate, JSON)                           │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.1 Crate layout

```
project-a/
├─ Cargo.toml                       # workspace
├─ crates/
│  ├─ slack-connector-core/         # traits, types, normalizer, filter
│  ├─ slack-sources/                # AuditPoller, EventsSocket, AccessPoller, WebPoller
│  ├─ wazuh-sinks/                  # UnixSocketSink, JsonFileSink, StdoutSink
│  ├─ slack-connector-cli/          # binary, config loader, supervisor
│  └─ slack-connector-test-fixtures/# bundled Slack payload samples
├─ config/
│  └─ wazuh-slack.yaml.example
├─ wazuh-rules/
│  └─ 0500-slack-rules.xml
├─ wazuh-decoders/
│  └─ 0501-slack-decoder.xml
└─ deploy/
   ├─ systemd/wazuh-slack.service
   ├─ ossec.conf.wodle.snippet
   └─ ossec.conf.localfile.snippet
```

### 5.2 Key dependencies

- `tokio` (rt-multi-thread, signal, fs, net)
- `reqwest` (rustls-tls, json, gzip)
- `slack-morphism` v2 (Events API + Socket Mode)
- `serde` / `serde_json` / `serde_yaml`
- `rusqlite` (cursor + dedup state)
- `tracing` + `tracing-subscriber` (json fmt)
- `metrics` + `metrics-exporter-prometheus`
- `keyring` (token storage, optional)
- `async-trait`, `anyhow`, `thiserror`, `governor` (rate limit), `backoff`

### 5.3 Filter / YAML config (user-customizable)

```yaml
slack:
  token_bot:    "${SLACK_BOT_TOKEN}"        # env interpolation
  token_user:   "${SLACK_USER_TOKEN}"        # required for audit logs
  token_app:    "${SLACK_APP_TOKEN}"         # required for socket mode
  org_id:       "E01ABCDEF"                  # required for audit
  sources:
    audit:        { enabled: true,  poll_seconds: 60 }
    events:       { enabled: true,  mode: socket }
    access_logs:  { enabled: false, poll_seconds: 300 }
    web_inventory:{ enabled: true,  poll_seconds: 3600 }

filters:
  # global drop list (applied to every source after normalization)
  drop:
    - field: slack.action
      in: [user_login_failed_unknown_user]   # too noisy
    - field: slack.actor.user.email
      regex_match: ".*@bot\\.local$"

  # per-source allow list (if present, only matches pass)
  audit:
    allow:
      - field: slack.action
        in: [user_login, user_login_failed, app_installed, app_uninstalled,
             file_public_link_created, member_joined_workspace, role_change_to_admin,
             tokens_revoked, mfa_disabled, sso_disabled, channel_created_external_shared]

  events:
    allow:
      - field: slack.event_type
        in: [tokens_revoked, app_uninstalled, file_public, member_joined_channel,
             channel_created, subteam_created, team_join]

severity_map:
  mfa_disabled:                   critical
  sso_disabled:                   critical
  role_change_to_admin:           high
  file_public_link_created:       medium
  app_installed:                  medium
  user_login_failed:              low

sink:
  kind: unix_socket
  unix_socket:
    path: /var/ossec/queue/sockets/queue
  spool:
    dir:  /var/lib/wazuh-slack/spool
    max_mb: 500

state:
  sqlite_path: /var/lib/wazuh-slack/state.db

observability:
  prometheus_bind: 0.0.0.0:9183
  log_level: info
```

### 5.4 Normalized event shape (what Wazuh sees)

```json
{
  "@timestamp": "2026-05-18T14:22:31Z",
  "slack": {
    "source": "audit",
    "action": "user_login_failed",
    "event_id": "Eabc123",
    "actor": { "type": "user", "id": "U123", "email": "..." },
    "entity": { "type": "workspace", "id": "T123" },
    "context": { "ip": "1.2.3.4", "ua": "...", "location": {...} }
  },
  "severity": "low",
  "raw": { ... full original Slack payload ... }
}
```

---

## 6. Resilience / Operational Concerns

- **At-least-once delivery**: cursors only advance after sink ACK. Dedup LRU on the Wazuh decoder side via `slack.event_id` (rule using `if_sid` + `same_field`).
- **Backpressure path**: source → bounded mpsc → sink. Channel full ⇒ source poller pauses (does NOT advance cursor) ⇒ Slack rate-limit-friendly.
- **Crash recovery**: SQLite cursors + on-disk spool replay before resuming polls.
- **Clock skew**: use Slack-provided timestamps as authoritative `@timestamp`, never local clock.
- **Observability**: counters per source (`events_received`, `events_filtered_out`, `events_sent`, `sink_errors`, `rate_limited_seconds_total`), histograms (`slack_request_duration`, `sink_emit_duration`), gauges (`spool_bytes`, `mpsc_queue_depth`).
- **Health**: `/healthz` returns 503 if any enabled source has been down > N min OR spool > 80% full.
- **Shutdown**: `SIGTERM` → stop sources → drain channel → flush sink → persist dedup LRU → exit.

---

## 7. Threat / Security Considerations

- TLS verification enforced on all Slack HTTP calls (rustls).
- Connector binary should run as unprivileged user (`wazuh` group for socket access). Document `setcap` only if absolutely needed.
- Tokens never logged. Redaction in `Debug` impl. `tracing` filter to strip `Authorization` headers.
- Spool files `0600`, state DB `0600`.
- Validate Slack Events signing secret (`X-Slack-Signature` + replay window) — applies if HTTP mode ever enabled; Socket Mode handles this transport-level.
- Supply chain: pin crate versions, `cargo deny` in CI, `cargo audit` on schedule.

---

## 8. Testing Strategy

| Layer | Approach |
|-------|----------|
| Normalizer | Unit tests against bundled JSON fixtures (audit, events, accessLogs) |
| FilterEngine | Property-style tests: golden-input → expected pass/drop |
| Sources | Mock Slack via `wiremock` crate; assert pagination, retry, rate-limit handling |
| Sinks | UnixSocketSink: spawn a fake AF_UNIX listener, assert wire format `1:slack-audit:...`. JsonFileSink: tmp dir + read-back. |
| End-to-end | Compose: local Wazuh manager (docker `wazuh/wazuh-manager`) + connector pointed at it + canned Slack mock → assert alert IDs appear in `/var/ossec/logs/alerts/alerts.json` |
| Wazuh rules | `wazuh-logtest` driven by fixture file, asserts rule IDs fire |
| Resilience | Inject sink failures, assert spool grows and replays |

---

## 9. Delivery Phases

| Phase | Deliverable |
|-------|-------------|
| **0. Bootstrap** | Cargo workspace, CI (fmt, clippy, test, audit), config loader, `StdoutSink`, basic Events API socket source |
| **1. Slack sources** | EventsSocket (full), AccessLogsPoller, WebInventoryPoller, AuditPoller (impl + Enterprise-only feature flag) |
| **2. Normalizer + filter engine** | YAML schema, normalizer with `slack.*` namespacing, filter eval, severity mapping |
| **3. Wazuh sinks** | UnixSocketSink with EAGAIN + spool, JsonFileSink with rotation |
| **4. Wazuh-side artifacts** | Rules XML (≥ 20 rules covering MFA, SSO, admin role, public file, app install, login fail bursts), decoder, deploy snippets |
| **5. Observability + ops** | Prometheus exporter, `/healthz`, systemd unit, structured logs |
| **6. E2E + docs** | Docker-compose dev stack, README, hardening guide, Enterprise-Grid prereqs doc |

---

## 10. Open Questions for User

(None blocking — defaults chosen, but flag for confirmation at exit-plan time.)

1. Wazuh deploy target was answered "I don't know yet" → plan ships both `UnixSocketSink` and `JsonFileSink`, user picks at install time. **No code-level decision blocked.**
2. Slack instance is free tier → Audit/Discovery/SCIM code paths are implemented but disabled on startup probe. **No code-level decision blocked**; reachable production needs Enterprise Grid.

---

## 11. Acceptance / Verification

Local dev verification (no Enterprise Slack needed):

```powershell
# 1. spin up dev Wazuh manager
docker run -d --name wazuh -p 1514:1514/udp -p 55000:55000 wazuh/wazuh-manager:4.9.0

# 2. point connector at it (JsonFileSink for cross-platform dev)
$env:SLACK_BOT_TOKEN="xoxb-..."
$env:SLACK_APP_TOKEN="xapp-..."
cargo run -p slack-connector-cli -- --config config/wazuh-slack.dev.yaml

# 3. trigger a Slack event in the dev workspace (join channel, share file)
# 4. assert NDJSON line appears in events.ndjson
# 5. assert alert appears in docker exec wazuh tail -f /var/ossec/logs/alerts/alerts.json
```

Production verification (Enterprise Grid):

```bash
# Manager-side install
sudo cp target/release/wazuh-slack /usr/local/bin/
sudo cp config/wazuh-slack.yaml /etc/wazuh-slack/
sudo cp wazuh-rules/0500-slack-rules.xml /var/ossec/etc/rules/
sudo cp wazuh-decoders/0501-slack-decoder.xml /var/ossec/etc/decoders/
sudo systemctl restart wazuh-manager wazuh-slack
# Verify with wazuh-logtest against fixture, then live for ≥ 1h.
```

---

## 12. References (from research)

- Slack Audit Logs API — https://api.slack.com/admins/audit-logs
- Slack Events API — https://api.slack.com/apis/events-api
- Slack Socket Mode — https://api.slack.com/apis/socket-mode
- Slack rate limits — https://api.slack.com/apis/rate-limits
- Wazuh Office365 wodle (reference impl) — `wazuh/wazuh` repo `wodles/office365/`
- Wazuh AWS wodle (cursor pattern) — `wodles/aws/aws_s3.py`
- Wazuh JSON decoder docs — https://documentation.wazuh.com/current/user-manual/ruleset/decoders/decoders-syntax.html
- Wazuh custom rules — https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html
- `slack-morphism` crate — https://docs.rs/slack-morphism
