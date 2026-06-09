# wazuh-slack — Command Reference

All commands run from project root (`project-a/`). Shell is PowerShell.

---

## 1. Build & toolchain

```powershell
rustc --version                 # toolchain pinned in rust-toolchain.toml (>=1.80)
cargo build                     # debug build (all workspace crates)
cargo build --release           # optimized build → target/release/wazuh-slack
cargo clean                     # wipe target/
```

## 2. Lint / format / test

```powershell
cargo fmt                       # format
cargo fmt --check               # CI format check
cargo clippy --all-targets --all-features -- -D warnings
cargo test                      # full workspace test suite
cargo test -p slack-connector-core   # single crate
```

## 3. CLI (the connector binary: `wazuh-slack`)

```powershell
# config validate only, no start
cargo run --release -- --config config/wazuh-slack.dev.yaml --check

# run connector
cargo run --release -- --config config/wazuh-slack.dev.yaml

# from built binary
./target/release/wazuh-slack --config config/wazuh-slack.example.yaml
```

Flags:
| Flag | Env | Default |
|---|---|---|
| `--config <path>` | `WAZUH_SLACK_CONFIG` | `config/wazuh-slack.yaml` |
| `--log-level <lvl>` | `WAZUH_SLACK_LOG_LEVEL` (or `RUST_LOG`) | `info` |
| `--check` | — | validate config + exit |

## 4. Quickstart — dev, no Wazuh

```powershell
# tokens go in PROCESS env (raw binary does NOT read .env)
$env:SLACK_BOT_TOKEN  = "xoxb-..."   # bot token
$env:SLACK_APP_TOKEN  = "xapp-..."   # app-level (Socket Mode)
$env:SLACK_USER_TOKEN = "xoxp-..."   # user token — Enterprise Grid audit source only

# enable events source in config/wazuh-slack.dev.yaml (events.enabled: true)
cargo run --release -- --config config/wazuh-slack.dev.yaml
# JsonFileSink → events.ndjson
```

## 5. Quickstart — full Wazuh stack (docker-compose)

Stack = manager + indexer + dashboard + connector.

```powershell
# PREREQ (Windows/WSL): bump map count or indexer crash-loops
wsl -d docker-desktop sysctl -w vm.max_map_count=262144

# 1. generate TLS certs ONCE → config/wazuh_indexer_ssl_certs/
docker compose -f generate-certs.yml run --rm generator

# 2. tokens (docker-compose auto-loads .env)
copy .env.example .env          # edit with real xoxb-/xapp- tokens

# 3. launch
docker compose up --build -d
```

Inline token form (no .env):
```powershell
$env:SLACK_BOT_TOKEN="xoxb-..."; $env:SLACK_APP_TOKEN="xapp-..."; docker compose up --build -d
```

## 6. Docker ops

```powershell
docker compose ps                       # status
docker compose logs -f wazuh-slack      # connector logs
docker compose logs -f wazuh.manager    # manager logs
docker compose down                     # stop
docker compose down -v                  # stop + wipe volumes (certs, state, logs)
docker compose restart wazuh-slack      # restart connector only
```

## 7. Endpoints

| What | URL / cmd |
|---|---|
| Dashboard UI | https://localhost  (admin / SecretPassword) |
| Indexer | https://localhost:9200 |
| Connector metrics (Prometheus) | http://localhost:9183/metrics |
| Connector health | http://localhost:9184/healthz |
| Alerts (file) | `docker compose exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.json` |

## 8. Demo & test signal

```powershell
# attack scenarios against docker stack
./scripts/demo.ps1 -Scenario all -Target docker
./scripts/demo.ps1 -Scenario channel-recon
./scripts/demo.ps1 -Scenario file-exfil
./scripts/demo.ps1 -Scenario replit

# rule/decoder logtest
./scripts/logtest.ps1 -Action member_joined_channel
./scripts/logtest.ps1 -Action file_downloaded -Source audit

# watch alerts land
docker compose exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.json
```

## 9. Production deploy (systemd, Unix socket sink)

```bash
cargo build --release      # run as wazuh user; /var/ossec/queue/sockets must be writable
./target/release/wazuh-slack --config config/wazuh-slack.example.yaml   # sink.kind: unix_socket
# service unit: scripts/systemd/wazuh-slack.service
```

---

### Config files
| File | Profile |
|---|---|
| `config/wazuh-slack.dev.yaml` | dev — JsonFileSink, local paths |
| `config/wazuh-slack.docker.yaml` | compose — JsonFileSink → shared volume |
| `config/wazuh-slack.example.yaml` | prod shape — UnixSocketSink |
