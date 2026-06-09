# Insider-Threat Detection — Gap Plan (to implement later)

Threat model: the "Replit pattern" — a privileged insider, over a short window,
accessing/pulling large volumes of data, often off-hours and from unusual
context. This file lists the detection gaps and the concrete changes to close
them. Nothing here is implemented yet.

Scope note: `auditlogs:read` (user token, org-installed) is the single unlock.
The normalizer (`crates/slack-sources/src/normalize.rs`) is already generic and
captures `actor`, `entity`, and `context` (IP / user-agent / geo) for any audit
action, so no new Slack scopes are required for the items below.

---

## Gap 1 — Audit filter allow-list starves new rules (do this FIRST)

**Problem:** `config/wazuh-slack.example.yaml` `filters.audit.allow` is an
allow-list of ~10 actions. Anything not listed is dropped before reaching Wazuh,
so `anomaly`, export actions, and login events never arrive — every rule below
would be starved without this change.

**Change:**
- Widen `filters.audit.allow` to include the actions the new rules need
  (`anomaly`, export actions, `user_login`), or remove the audit allow-list and
  rely on `filters.drop` for noise reduction instead.
- Apply the same widening to the dev/docker configs used for testing.

**Files:** `config/wazuh-slack.example.yaml`, `config/wazuh-slack.dev.yaml`,
`config/wazuh-slack.docker.yaml`.

**Acceptance:** with audit enabled, an `anomaly` / export / `user_login` event
reaches the sink (not counted in `wsc_events_filtered_total`).

---

## Gap 2 — Surface Slack's own anomaly detection (`anomaly` action)

**Problem:** Slack Enterprise runs its own anomaly detection (excessive
downloads, suspicious login, token theft) and emits audit `action: anomaly`.
No rule matches it. This is the closest direct signal to "abnormal activity."

**Change:** add a rule in `wazuh-rules/0500-slack-rules.xml` (new ID, e.g.
100080) matching `slack.source=audit` + `slack.action=anomaly`, level ~12.
Consider mapping anomaly sub-types from `raw` into the description.

**Files:** `wazuh-rules/0500-slack-rules.xml`; add `anomaly` to allow-list
(Gap 1); optional `severity_map` entry.

**Acceptance:** synthetic `anomaly` audit event raises a level-12+ alert.

---

## Gap 3 — Data / workspace export detection

**Problem:** a privileged user exporting a workspace is the loudest exfil
signal and is currently invisible. Audit actions like `export_started`,
`workspace_exported`, `organization_exported` are not covered.

**Change:** add rules (e.g. 100081–100083) for the export action set,
level 12–13. Treat org-level export as critical.

**Files:** `wazuh-rules/0500-slack-rules.xml`; allow-list (Gap 1).

**Acceptance:** synthetic export audit event raises a high/critical alert.

---

## Gap 4 — Login context anomaly (new IP / geo)

**Problem:** the normalizer captures `slack.context.ip` and
`slack.context.location` on audit events, but **no rule reads them**. New-IP /
unusual-country logins go undetected.

**Change:**
- Add a `user_login` rule that flags logins whose `slack.context.location`
  country is not in an allow CDB list, or whose IP is not in a known-good CDB
  list. Use Wazuh CDB lists (`lists/`) + `<list>` lookups.
- Full impossible-travel (velocity) is out of scope for stateless Wazuh; CDB
  allow-listing covers ~80%. Note this limitation in the rule comment.

**Files:** `wazuh-rules/0500-slack-rules.xml`; new CDB list under `lists/` +
`ossec.conf` reference; allow-list must pass `user_login` (Gap 1).

**Acceptance:** `user_login` from a country/IP outside the allow list raises an
alert; in-list logins stay silent.

---

## Gap 5 — Off-hours activity burst

**Problem:** no time-of-day awareness. A download/share burst at 03:00 looks the
same as midday.

**Change:** add frequency rules scoped by `slack.actor.id` for
`file_downloaded` / `file_shared` that fire at a lower threshold during
off-hours. Implement via Wazuh `<time>`/`<day>` rule options or a derived
field; document the business-hours assumption.

**Files:** `wazuh-rules/0500-slack-rules.xml`.

**Acceptance:** a download burst inside the off-hours window alerts at a lower
threshold than the daytime rule (100051).

---

## Gap 6 — `access_logs` source sends the wrong token (code fix)

**Problem:** `crates/slack-connector-cli/src/supervisor.rs:204` builds
`AccessLogsPoller` with `token_bot`; Slack rejects `team.accessLogs` for bot
tokens (`not_allowed_token_type`, confirmed in live test).

**Change:** pass `token_user` to the access-logs poller (and update
`AccessLogsPoller` field/docs accordingly). Lower priority — audit logs already
carry richer login + IP data.

**Files:** `crates/slack-connector-cli/src/supervisor.rs`,
`crates/slack-sources/src/access_logs.rs`.

**Acceptance:** with a user token holding `admin`, `team.accessLogs` returns
`ok:true` and login events flow.

---

## Known limitation (not a gap to fix) — message search is not observable

Slack's Audit Logs API does **not** log message search queries. The literal
"frantic searching" action cannot be captured via any scope. Detection relies on
what the insider *does with* findings — mass downloads, exports, public links,
channel recon — all covered by Gaps 2–5 plus existing rules.

---

## Suggested order

1. Gap 1 (filter) — unblocks everything else.
2. Gaps 2 + 3 (anomaly, export) — highest signal, lowest effort.
3. Gap 4 (login context) — needs CDB lists.
4. Gap 5 (off-hours).
5. Gap 6 (access_logs code) — optional.

## Validation plan

Extend `scripts/demo.ps1` with synthetic `anomaly`, export, and off-hours
download-burst scenarios; confirm each new rule fires in
`/var/ossec/logs/alerts/alerts.json`. Reserve rule IDs 100080–100099.
