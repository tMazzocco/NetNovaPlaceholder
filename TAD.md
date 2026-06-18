# Technical Architecture Document — wazuh-slack

> English counterpart of a French *Document d'Architecture Technique (DAT)*,
> refined for this project. Describes the as-built architecture of the
> Slack → Wazuh connector.

| | |
|---|---|
| **Project** | wazuh-slack connector |
| **Version** | 0.1.0 |
| **Status** | PoC — core pipeline validated end-to-end (incl. live Enterprise Grid audit) |
| **Language / edition** | Rust (stable, MSRV 1.80, edition 2021) |
| **Last updated** | 2026-06-09 |
| **Related docs** | `README.md` (operator guide), `p.md` (implementation plan), `INSIDER-THREAT-GAPS.md` (detection roadmap) |

---

## 1. Purpose & context

Wazuh ships first-party wodles for Office 365, GitHub, AWS, Azure and GCP, but
**no Slack source connector** — the stock `integrations/slack` runs the opposite
direction (Wazuh alerts → Slack webhook). This project fills that gap: a Rust
daemon that ingests Slack security/activity telemetry, normalizes it to a single
canonical schema, applies user-defined filtering, and delivers it into Wazuh's
analysis pipeline (analysisd) so it can be decoded, correlated by stateful rules,
and surfaced in the Wazuh dashboard alongside other SIEM data.

**Primary mission:** abnormal user-behaviour / insider-threat detection (the 2024
Replit case — a privileged user exfiltrating data over a short window), using
Wazuh's stateful frequency rules for correlation.

### 1.1 Why Rust
Single static binary (trivial deploy on a Wazuh manager/agent host), memory
safety, no GC pauses for a long-running poller, mature async stack (Tokio,
reqwest, slack-morphism), and a smaller footprint than the Python stock wodles.

---

## 2. Scope

**In scope (v1):** Events API (Socket Mode), Audit Logs API, `team.accessLogs`
polling, Web API inventory snapshots; normalization; filtering; three sinks;
Wazuh decoder + rules; observability; docker-compose full-stack PoC.

**Out of scope (v1):** Discovery API (DLP/eDiscovery — requires Slack-approved
app), SCIM, OAuth token rotation refresher (config scaffolding only, parsed but
not acted on), message-content search visibility (not exposed by any Slack API).

---

## 3. Architecture overview

The connector is a single multi-threaded Tokio process structured as a fan-in
pipeline: N independent source tasks → bounded channel → one dispatcher that
filters and emits to a single sink.

```
        Slack APIs
 ┌───────────┬───────────┬──────────────┬──────────────┐
 │ Events    │ Audit     │ team.access  │ Web API       │
 │ (Socket)  │ Logs      │ Logs         │ (users/convo) │
 └─────┬─────┴─────┬─────┴──────┬───────┴───────┬───────┘
       ▼           ▼            ▼               ▼
  EventsSocket  AuditPoller  AccessLogs   WebInventory      ← LogSource impls
       │           │            │               │             (async tasks)
       │      normalize_*  + dedup (events)      │
       └───────────┴───────┬────┴───────────────┘
                           ▼
               tokio::mpsc<NormalizedEvent> (bounded, 10 000)
                           ▼
                   ┌───────────────┐
                   │  Dispatcher   │  severity_map → global drop → per-source allow
                   │ (FilterEngine)│
                   └───────┬───────┘
                           ▼
                   WazuhSink (one of):
        ┌────────────────┬──────────────────┬──────────────┐
        │ UnixSocketSink │ JsonFileSink      │ StdoutSink   │
        │ analysisd queue│ NDJSON + rotate   │ dev/debug    │
        └────────┬───────┴─────────┬─────────┴──────────────┘
                 ▼                 ▼
          Wazuh analysisd   localfile tail → analysisd
                 └──────────┬──────────┘
                            ▼
                 decoder (0501) → rules (0500) → alerts.json → indexer → dashboard
```

Cross-cutting: a startup **tier probe** detects workspace capabilities and
disables unsupported sources; a **SQLite state store** persists poll cursors; a
**health endpoint** and **Prometheus exporter** provide observability.

---

## 4. Component architecture (Cargo workspace)

Five crates, resolver 2. Release profile: `lto = "thin"`, `codegen-units = 1`,
`strip = "debuginfo"`.

| Crate | Responsibility | Key items |
|---|---|---|
| `slack-connector-core` | Domain types, traits, config, filtering | `NormalizedEvent`, `SourceTag`, `Severity`, `LogSource`, `WazuhSink`, `Config`, `FilterEngine` |
| `slack-sources` | Slack ingestion + per-source normalization | `EventsSocketSource`, `AuditPoller`, `AccessLogsPoller`, `WebInventoryPoller`, `TierProbe`, `DedupCache`, `StateStore`, `normalize_*` |
| `wazuh-sinks` | Output adapters | `UnixSocketSink`, `JsonFileSink`, `StdoutSink` |
| `slack-connector-cli` | Binary `wazuh-slack`: CLI, supervisor, observability, health | `Cli`, `run_supervisor`, metrics init, `/healthz` |
| `slack-connector-test-fixtures` | Slack JSON samples for tests | `AUDIT_*`, `EVENTS_*` |

### 4.1 Core traits
- **`LogSource`** (`async_trait`): `kind() -> SourceKind` and
  `run(self, tx: mpsc::Sender<NormalizedEvent>, shutdown: watch::Receiver<bool>)`.
  Every source is a uniform async task; the supervisor owns the registry.
- **`WazuhSink`** (`async_trait`): `emit(&NormalizedEvent)` and `flush()`. One
  active sink per process, selected by config.

### 4.2 Key third-party dependencies
`tokio` 1 (multi-thread rt), `reqwest` 0.12 (rustls-TLS, no OpenSSL),
`slack-morphism` 2 (hyper, Socket Mode), `rusqlite` 0.32 (bundled SQLite),
`metrics` 0.24 + `metrics-exporter-prometheus` 0.16, `lru` 0.12, `parking_lot`,
`governor`/`backoff` (rate-limit/backoff), `clap` 4, `tracing` (+ JSON subscriber),
`serde`/`serde_json`/`serde_yaml`, `chrono`.

---

## 5. Canonical data model

All sources converge on one schema (`event.rs`), serialized as JSON with an
ELK-style `@timestamp`. Optional fields are omitted when absent.

```jsonc
{
  "@timestamp": "2026-06-09T10:23:34Z",
  "slack": {
    "source":   "audit|events|accesslogs|webinventory",
    "action":   "file_downloaded",          // verbatim Slack action / event type
    "event_id": "...",                        // dedup / idempotency key
    "actor":    { "type": "user", "id": "U…", "name": "…", "email": "…" },
    "entity":   { "type": "file|channel|workspace", "id": "F…", "name": "…" },
    "context":  { "ip": "203.0.113.10", "ua": "…", "location": { … } }
  },
  "severity": "info|low|medium|high|critical",
  "raw": { … }                                // original Slack payload, preserved
}
```

Design notes:
- **`raw` is always preserved** so rules can reach fields the normalizer doesn't
  promote, and so nothing is lost in translation.
- **`context` (IP / UA / geo)** is populated for audit events — the substrate for
  login-anomaly detection (currently unused by rules; see gaps).
- **Field lookup** for filtering uses dotted paths (`slack.actor.email`,
  `raw.x.y`) via `NormalizedEvent::lookup`.
- `SourceTag::location_tag()` maps source → Wazuh `location` string
  (`slack-audit`, `slack-events`, `slack-access`, `slack-inventory`).

---

## 6. Sources (ingestion)

| Source | Slack interface | Token | Cursor / state key | Tier |
|---|---|---|---|---|
| Events | Socket Mode WebSocket (`slack-morphism`) | `xapp-` + `xoxb-` | in-memory dedup LRU | any |
| Audit | `GET api.slack.com/audit/v1/logs` (reqwest) | `xoxp-` (`auditlogs:read`) | `audit.oldest`, `audit.cursor` | Enterprise Grid |
| Access logs | `GET slack.com/api/team.accessLogs` | **should be `xoxp-`/`admin`** (see §12) | `access_logs.date_first` | Pro+ |
| Web inventory | `users.list` + `conversations.list` | `xoxb-` | `web_inventory.last_run` | any |

- **Events** — outbound WebSocket (no public ingress on the Wazuh host). Push
  callbacks are re-serialized to JSON and normalized. Redeliveries (Slack retries
  on missed 3 s ACK) are suppressed by a bounded **LRU dedup cache** (10 000
  `event_id`s, in-memory).
- **Audit** — cursor pagination (`limit=200`), persists `oldest`/`cursor` in
  SQLite for restart-safe resume. Honours HTTP 429 `Retry-After`; treats
  401/403 as a fatal scope/tier error.
- **Access logs** — page-based; advances on `date_first`; clamped by a backfill
  floor (`backfill_days`, default 90) so cold starts don't scan empty history.
- **Web inventory** — low-frequency full snapshot (users + channels) to catch
  what the Events API doesn't push (silent integrations, guests); diffable.

### 6.1 Tier probe (`TierProbe`)
At startup, when a bot token is present:
1. `auth.test` → `team_id`, `enterprise_id`, `user_id` (presence of
   `enterprise_id` ⇒ Enterprise Grid).
2. `team.accessLogs?count=1` → `ok` ⇒ Paid; `paid_only` ⇒ Free.
3. `audit/v1/schemas` with the user token → audit availability.

The supervisor uses the result to skip sources the workspace/token can't serve,
logging a warning instead of failing. *(Verified 2026-06-09 on a live Grid org:
`tier: Enterprise`, `audit_logs: true`.)*

---

## 7. Processing — filter & severity

`FilterEngine::evaluate` runs per event in the dispatcher, in order:
1. **Severity map** — override `severity` from `severity_map[action]` first, so
   downstream sees the final value even if later dropped.
2. **Global drop** — if **any** `filters.drop` rule matches, drop the event.
3. **Per-source allow** — if an allow-list exists for the event's source, the
   event must match **at least one** rule, else drop.

Match operators (`MatchOp`): `eq`, `in`, `regex_match`, `exists`. Rules address
fields by dotted path against the serialized event.

> Operational consequence: a non-empty per-source allow-list is a **whitelist** —
> unlisted actions are silently dropped before Wazuh. This is the root of Gap 1
> (prod audit allow-list starves new detections).

---

## 8. Sinks (delivery)

| Sink | Target | Behaviour |
|---|---|---|
| `UnixSocketSink` | analysisd queue socket (Unix only) | OSSEC wire format `1:<location>:<json>`; datagram send |
| `JsonFileSink` | NDJSON file | one JSON/line; size-based rotation (`rotate_mb`) |
| `StdoutSink` | stdout | dev/debug |

**UnixSocketSink resilience:** on `EAGAIN`/`WouldBlock` (analysisd queue full),
retries up to 5 times with exponential backoff (25 ms → max 1000 ms). On a hard
send error or exhausted retries it **spools** to hourly NDJSON segments
(`<dir>/%Y%m%dT%H.ndjson`) and warns if a segment exceeds the configured cap.
Spooling makes back-pressure non-lossy; a future replayer drains spool → socket.

---

## 9. Deployment architecture

Three supported topologies:

**A. Manager co-located (production shape).** Connector runs on the Wazuh
manager host as a systemd unit (`deploy/systemd/wazuh-slack.service`), writing
directly to the analysisd queue via `UnixSocketSink`
(`/var/ossec/queue/sockets/queue`). Lowest latency; needs the wazuh user + socket
permissions.

**B. Agent-side file tail.** Connector writes NDJSON via `JsonFileSink`; a Wazuh
`<localfile>` (`deploy/ossec.conf.localfile.snippet`) tails it. Decouples the
connector from manager internals.

**C. Full stack via docker-compose (PoC).** Four services — `wazuh.manager`
(analysisd/decoder/rules → `alerts.json`), `wazuh.indexer` (OpenSearch fork),
`wazuh.dashboard` (Kibana fork), and `wazuh-slack` (this connector). The
connector writes into a shared `slack-logs` volume the manager tails; SQLite
state persists on `slack-state`. TLS certs are generated once via
`generate-certs.yml`.

Build: multi-stage `Dockerfile`; secrets supplied via `.env` (compose
auto-loads; the **raw binary does not** — env vars must be exported).

---

## 10. Configuration

Single YAML file (`-c/--config`, env `WAZUH_SLACK_CONFIG`), with `${VAR}`
environment interpolation (fails fast if a referenced var is unset) and
`#[serde(deny_unknown_fields)]` (typos rejected). `--check` validates and exits.

Profiles: `wazuh-slack.dev.yaml` (JsonFileSink, local paths),
`wazuh-slack.docker.yaml` (JsonFileSink → shared volume),
`wazuh-slack.example.yaml` (UnixSocketSink, prod shape). Top-level keys: `slack`
(tokens, org_id, backfill_days, rotation, sources), `filters`, `severity_map`,
`sink`, `state`, `observability`.

---

## 11. Cross-cutting concerns

### 11.1 Security
- **Secrets** never live in config files — only `${ENV}` references; tokens come
  from the process environment (`.env` / systemd `EnvironmentFile` / container
  secrets). Logs never print token values.
- **Least privilege** — three scoped tokens: bot (`xoxb-`, read scopes), app
  (`xapp-`, `connections:write`), user (`xoxp-`, `auditlogs:read`, Grid-only,
  org-installed). The user token must be **distinct** from the bot token.
- **Network** — Socket Mode uses an **outbound** WebSocket, so no inbound ingress
  is required on the Wazuh host. TLS via rustls (no OpenSSL).
- **Transport to Wazuh** — local Unix datagram or local file; no network sink.

### 11.2 Reliability & error handling
- **Restart-safe cursors** in SQLite (`rusqlite`, bundled) per poll source.
- **Dedup** of Events redeliveries (bounded LRU, in-memory).
- **Rate limiting** — audit honours 429 `Retry-After`; Audit Logs API is a
  shared org-wide Tier-3 budget (~50 req/min), so backoff is mandatory.
- **Back-pressure** — bounded mpsc (10 000); UnixSocket ret/spool path prevents
  loss when analysisd is saturated.
- **Backfill clamp** — `backfill_days` (default 90) bounds cold-start scans.
- **Graceful shutdown** — `watch` channel fans a shutdown signal to all sources
  on Ctrl-C; dispatcher flushes the sink before exit.
- **Degradation** — unusable sources are skipped (probe-driven), not fatal.

### 11.3 Observability
- **Metrics** (`GET /metrics`, `observability.prometheus_bind`):
  `wsc_events_received_total{source}`, `wsc_events_filtered_total`,
  `wsc_events_emitted_total{source}`, `wsc_sink_errors_total`.
- **Health** (`GET /healthz`, `observability.health_bind`): JSON liveness; `200`
  healthy, `503` while starting or when poll sources go **stale** (no output for
  3× the longest poll interval, floor 300 s). Pure push setups never stale (no
  cadence). Wired to the container `healthcheck`.
- **Logging** — structured JSON via `tracing` (`RUST_LOG` / `--log-level`).

### 11.4 Performance & footprint
Multi-threaded Tokio; sources are independent tasks; single static binary; thin
LTO release build. I/O-bound workload (HTTP polls + one WebSocket) — concurrency,
not CPU, is the constraint.

---

## 12. Detection content (Wazuh)

- **Decoder** `wazuh-decoders/0501-slack-decoder.xml` — JSON plugin decoder; a
  `slack` parent plus per-source children keyed on the `location` tag.
- **Rules** `wazuh-rules/0500-slack-rules.xml` — IDs 100000–100099, group
  `slack`. Base catch-all (100000) + behavioural rules: channel-join recon
  (100011, ≥20/1 h), file-share/public-link exfil (100021/100026),
  auth/integration events, and Enterprise audit rules — the headline
  **file-download burst** (100051, ≥50/24 h = Replit pattern), MFA/SSO disabled,
  admin role grant, external channel / guest creation.

Severity → Wazuh level convention: info→3, low→5, medium→8, high→10, critical→13.

`scripts/demo.ps1` injects synthetic NormalizedEvent bursts through the real
decoder+rule chain (no Slack needed); `scripts/logtest.ps1` does single-event
`wazuh-logtest` checks.

---

## 13. Tier capability matrix

| Detection | Free | Pro/Business+ | Enterprise Grid |
|---|---|---|---|
| Channel-join / file-share / public-link bursts | ✅ Events | ✅ | ✅ |
| App install/uninstall, tokens revoked | ✅ Events | ✅ | ✅ |
| Login-failure brute force | ❌ | ✅ `team.accessLogs` | ✅ Audit Logs |
| **File-download burst (Replit)** | ❌ | ❌ | ✅ Audit `file_downloaded` |
| MFA/SSO disabled, admin grant | ❌ | ❌ | ✅ Audit Logs |
| Search-query volume | ❌ | ❌ | ⚠️ Discovery API only (not implemented) |

---

## 14. Constraints, assumptions, risks

- **Audit Logs API requires Enterprise Grid** + org-installed app + `auditlogs:read`
  user token. Most high-value insider signals depend on it.
- **Message *search* is not observable** via any Slack API — "frantic searching"
  is detectable only through its side effects (downloads, exports, public links).
- **Audit Logs rate budget is org-wide and shared** across all apps — aggressive
  polling can starve other consumers.
- **Token assumption** — non-expiring internal/custom app tokens. Rotation is
  scaffolded but not implemented (warns if configured).

---

## 15. Known issues & roadmap

Tracked in `INSIDER-THREAT-GAPS.md` — **all six closed (2026-06-10):**
1. **Gap 1** ✅ — `filters.audit.allow` widened to pass `anomaly` / export / login
   actions (still a whitelist — keep in sync with rules).
2. **Gap 2** ✅ — rule 100080 matches the `anomaly` audit action.
3. **Gap 3** ✅ — rules 100081–100083 cover `export_*` / `*_exported`.
4. **Gap 4** ✅ — rules 100090–100092 read `slack.context.ip` / `.location` against
   CDB allow-lists in `wazuh-lists/` (impossible-travel still out of scope).
5. **Gap 5** ✅ — rule 100094 adds an off-hours `<time>`-gated download burst
   at a lower threshold than 100051.
6. **Gap 6** ✅ — `AccessLogsPoller` + `supervisor.rs` now use `token_user`.

Build status (PoC): bootstrap, sources, filter/normalizer, sinks, rules+decoder,
observability, and docker-compose E2E are complete; `WebInventoryPoller` and
`team.accessLogs` (user token) both work; insider-threat gaps 1–6 implemented.

---

## 16. Glossary

| Term | Meaning |
|---|---|
| analysisd | Wazuh manager component that decodes events and evaluates rules |
| wodle | Wazuh module/connector for an external data source |
| Socket Mode | Slack outbound-WebSocket transport for the Events API (no public ingress) |
| Audit Logs API | Enterprise-Grid-only org audit trail (`api.slack.com/audit/v1`) |
| Spool | On-disk buffer used when the analysisd socket is unavailable |
| Tier probe | Startup self-test that detects which Slack APIs the token can use |
| NormalizedEvent | The connector's canonical internal event schema |
