# CCDC Hardening Tracker

A small agent + Go server + LLM toolkit to track a blue team's Linux hardening
progress during a CCDC-style competition. Each host runs a collector script that
dumps its security-relevant state and POSTs it to a central server. The server
stores one report per host, serves the dashboard, and can call an LLM to produce
a prioritized diagnosis with copy-paste fix commands.

The agent only reads state; it never changes anything. Password hashes are never
exported, only their status (`set` / `locked` / `EMPTY!`).

```text
[ host 1 ] --+
[ host 2 ] --+--> POST /report --> server.go --/analyze--> analyzer.py --> LLM
[ host 3 ] --+       stores one JSON per host                  + dashboard at /
```

## Requirements

- Server: Go 1.22+.
- LLM analysis: Python 3.9+ plus `anthropic` and/or `openai`.
- Agents: `bash`, `base64`, and `curl` or `wget`.

Install Python analyzer dependencies only if you will use `/analyze/<host>`:

```bash
pip install anthropic openai
```

## Project Layout

```text
hardening_agent.sh   # Linux collector: collects state + phones home
server.go            # Go HTTP server: receives reports, dashboard, analysis routes
analyzer.py          # LLM prompt builder and Anthropic/OpenAI client wrapper
server.py            # legacy FastAPI server kept for compatibility
reports/             # generated reports and analyses; do not commit sensitive output
```

## Quick Start

Start the Go server:

```bash
export HARDEN_TOKEN="ccdcagent2026"      # optional; this is already the default
export ANTHROPIC_API_KEY="sk-ant-..."
go run .
```

The server listens on `:8000` by default. Override it with `HARDEN_ADDR`:

```bash
HARDEN_ADDR="0.0.0.0:8000" go run .
```

To use OpenAI instead:

```bash
export HARDEN_LLM_PROVIDER="openai"
export OPENAI_API_KEY="sk-..."
export HARDEN_MODEL="gpt-4o"             # optional; default is gpt-4o
go run .
```

Open `http://SERVER:8000/` for the dashboard.

Run the agent on each host as root for full coverage:

```bash
sudo HARDEN_SERVER="http://SERVER:8000/report" \
     HARDEN_TOKEN="ccdcagent2026" \
     ./hardening_agent.sh send
```

Try the agent locally first, without sending anything:

```bash
sudo ./hardening_agent.sh text
sudo ./hardening_agent.sh local
```

Get a diagnosis for a host:

```bash
curl -X POST http://SERVER:8000/analyze/web01
```

## HTTP API

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/report` | Agent submits a report with `X-Auth-Token` |
| `POST` | `/analyze/<host>` | Runs the LLM diagnosis and saves text output |
| `GET` | `/analysis/<host>` | Shows the saved diagnosis as HTML or text |
| `GET` | `/analysis/<host>?raw=1` | Returns the saved diagnosis as raw text |
| `GET` | `/report/<host>` | Returns the decoded raw collection report |
| `GET` | `/` | Dashboard listing all hosts |

## Configuration

| Variable | Used by | Default | Meaning |
|----------|---------|---------|---------|
| `HARDEN_SERVER` | agent | `http://127.0.0.1:8000/report` | Where agents POST reports |
| `HARDEN_TOKEN` | agent + server | `ccdcagent2026` | Shared token; must match |
| `HARDEN_ADDR` | server | `:8000` | Go server listen address |
| `HARDEN_DATA` | server | `./reports` | Where reports and analyses are stored |
| `HARDEN_PYTHON` | server | `python3` | Python executable used to run `analyzer.py` |
| `HARDEN_FIND_TIMEOUT` | agent | `25` | Per-`find` timeout in seconds |
| `HARDEN_LLM_PROVIDER` | analyzer | `anthropic` unless only `OPENAI_API_KEY` is set | `anthropic` or `openai` |
| `HARDEN_MODEL` | analyzer | `claude-sonnet-4-5` for Anthropic, `gpt-4o` for OpenAI | LLM model id |
| `HARDEN_MAX_CHARS` | analyzer | `120000` | Truncate very large reports before sending to the LLM |
| `ANTHROPIC_API_KEY` | analyzer | unset | Anthropic API key |
| `OPENAI_API_KEY` | analyzer | unset | OpenAI API key |

## Validation

```bash
GOCACHE=/private/tmp/ccdc-go-cache go test ./...
bash -n hardening_agent.sh
python3 -m py_compile analyzer.py server.py
```

For a manual smoke test:

```bash
go run .
sudo HARDEN_SERVER="http://127.0.0.1:8000/report" HARDEN_TOKEN="ccdcagent2026" ./hardening_agent.sh send
curl -X POST http://127.0.0.1:8000/analyze/$(hostname)
```

## Automating Agents

Install the script once, then use cron or a systemd timer so it phones home on a
schedule.

```bash
sudo cp hardening_agent.sh /usr/local/bin/hardening_agent.sh
sudo chmod +x /usr/local/bin/hardening_agent.sh
```

Cron example, every 10 minutes:

```bash
echo '*/10 * * * * root HARDEN_SERVER=http://SERVER:8000/report HARDEN_TOKEN=ccdcagent2026 /usr/local/bin/hardening_agent.sh send >/var/log/harden-agent.log 2>&1' \
  | sudo tee /etc/cron.d/hardening-agent
```

Systemd service:

```ini
[Unit]
Description=CCDC hardening collector

[Service]
Type=oneshot
Environment=HARDEN_SERVER=http://SERVER:8000/report
Environment=HARDEN_TOKEN=ccdcagent2026
ExecStart=/usr/local/bin/hardening_agent.sh send
```

Systemd timer:

```ini
[Unit]
Description=Run the CCDC hardening collector periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hardening-agent.timer
```

## Security Notes

- Use TLS through nginx/caddy or keep the server strictly on the internal
  competition network. Reports contain sensitive host state.
- `HARDEN_TOKEN` only blocks casual spam; do not treat it as strong auth.
- Do not commit API keys, shared tokens, or generated host reports.
- The central server aggregates sensitive data from every host. Isolate it.
