# CCDC Hardening Tracker

A small agent + Go server + LLM toolkit to track a blue team's Linux hardening
progress during a CCDC-style competition. Each host runs a collector script that
dumps its security-relevant state and POSTs it to a central server. The server
keeps the latest report plus an archive of every submission, serves an operator
dashboard, and can call an LLM to produce a prioritized diagnosis with
copy-paste fix commands.

The agent only reads state; it never changes anything. Password hashes are never
exported, only their status (`set` / `locked` / `EMPTY!`).

```text
[ host 1 ] --+
[ host 2 ] --+--> POST /report --> server.go --/analyze--> analyzer.py --> LLM
[ host 3 ] --+       latest + history archive                 + dashboard at /
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
pdf.go               # Styled, multipage PDF analysis renderer
dashboard.css        # Dashboard/report/history styles embedded into the Go binary
analyzer.py          # LLM prompt builder and Anthropic/OpenAI client wrapper
server.py            # legacy FastAPI server kept for compatibility
reports/             # generated reports and analyses; do not commit sensitive output
```

## Quick Start

Start the Go server:

```bash
export HARDEN_TOKEN="ccdcagent2026"      # optional; this is already the default
export HARDEN_UI_TOKEN="replace-with-a-separate-operator-secret"
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
export HARDEN_MODEL="gpt-5-mini"         # optional; default is gpt-5-mini
go run .
```

Open `http://SERVER:8000/` for the dashboard. Browser authentication is enabled
by default: enter any username and use `HARDEN_UI_TOKEN` as the password. If
`HARDEN_UI_TOKEN` is unset, the server falls back to `HARDEN_TOKEN` for
compatibility and logs a security warning. Use separate values in real matches
so a compromised collector cannot authenticate as an operator.

### Web experience

- The fleet dashboard prioritizes hosts by report freshness, collection
  coverage, collection identity, and analysis state. It includes host search
  and filters for reports that need attention, are stale, or were collected
  without root coverage.
- A report opens as an HTML section viewer with section navigation, search,
  expand/collapse controls, line wrapping, and per-section copy actions. Use
  `?raw=1` when exact plain text is preferable.
- History is a timeline instead of a timestamp table. It merges the current
  report with its matching latest snapshot, summarizes changed sections and
  added/removed lines, links each capture to its saved analysis when available,
  and paginates archived captures in groups of 25.
- Analysis state is `pending`, `current`, `stale`, or `failed`. An existing
  analysis becomes stale when a newer report is stored. The dashboard opens
  existing analyses and only starts pending ones; refresh actions stay on the
  analysis page.
- PDF downloads use the dashboard palette and render the score, executive
  summary, metadata, findings, tables, commands, continuations, and page footers
  as a structured operational report.

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
curl -H "X-Auth-Token: $HARDEN_UI_TOKEN" -X POST http://SERVER:8000/analyze/web01
```

## HTTP API

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/report` | Agent submits a report with `X-Auth-Token`; the latest report is stored at `<host>.json` and every submission is also archived under `history/<host>/` |
| `POST` | `/analyze/<host>` | Runs the LLM diagnosis and saves it with the current report and its matching history capture |
| `GET` | `/analysis/<host>` | Shows the saved diagnosis as HTML or text and flags it when a newer report makes it stale |
| `GET` | `/analysis/<host>?stamp=<timestamp>` | Shows the analysis saved for one historical report |
| `GET` | `/analysis/<host>?raw=1` | Returns the saved diagnosis as raw text |
| `GET` | `/analysis/<host>?format=md` | Downloads the saved diagnosis as a `.md` file |
| `GET` | `/analysis/<host>?format=pdf` | Downloads the saved diagnosis as a generated PDF |
| `GET` | `/report/<host>` | Shows the latest decoded report as the HTML section viewer or plain text |
| `GET` | `/report/<host>?raw=1` | Returns the latest decoded report as plain text |
| `GET` | `/history/<host>` | Shows the deduplicated change timeline; HTML pages contain 25 archived captures |
| `GET` | `/history/<host>?page=N` | Opens an older or newer HTML timeline page |
| `GET` | `/history/<host>/<timestamp>` | Shows an archived report as HTML or plain text |
| `GET` | `/healthz` | Returns `{"status":"ok"}` while the server data directory is available, otherwise HTTP 503 |
| `GET` | `/` | Dashboard showing fleet freshness, coverage, and analysis state |

The report, history, and analysis routes negotiate their representation. A web
browser sends `Accept: text/html` and receives the interactive HTML view. Plain
`curl` normally sends `Accept: */*`, so existing command-line use continues to
receive text: decoded report text, archived timestamps, or analysis text. Add an
HTML accept header to request the browser view explicitly; `?raw=1` always
selects plain text even when HTML is accepted. Agent ingestion uses
`HARDEN_TOKEN`; operator API calls and browser Basic authentication use
`HARDEN_UI_TOKEN` (or the compatibility fallback to `HARDEN_TOKEN`).
`/healthz` remains public for monitoring.

```bash
curl -H "X-Auth-Token: $HARDEN_UI_TOKEN" http://SERVER:8000/report/web01
curl -H "X-Auth-Token: $HARDEN_UI_TOKEN" -H 'Accept: text/html' http://SERVER:8000/report/web01
curl -H "X-Auth-Token: $HARDEN_UI_TOKEN" -H 'Accept: text/html' 'http://SERVER:8000/history/web01?page=2'
curl -H "X-Auth-Token: $HARDEN_UI_TOKEN" -H 'Accept: text/html' 'http://SERVER:8000/report/web01?raw=1'
```

## Configuration

| Variable | Used by | Default | Meaning |
|----------|---------|---------|---------|
| `HARDEN_SERVER` | agent | `http://127.0.0.1:8000/report` | Where agents POST reports |
| `HARDEN_TOKEN` | agent + server | `ccdcagent2026` | Shared token; must match |
| `HARDEN_UI_TOKEN` | server | falls back to `HARDEN_TOKEN` | Separate operator secret for dashboard, report, history, and analysis access; strongly recommended |
| `HARDEN_ADDR` | server | `:8000` | Go server listen address |
| `HARDEN_DATA` | server | `./reports` | Where reports and analyses are stored |
| `HARDEN_PROTECT_UI` | server | `true` | Require the operator token on dashboard, report, history, analysis, and analyze routes; set `false` only on an isolated trusted network |
| `HARDEN_PYTHON` | server | `python3` | Python executable used to run `analyzer.py` |
| `HARDEN_STALE_AFTER` | server | `15m` | Go duration after which the dashboard marks a report stale, such as `30m` or `1h` |
| `HARDEN_ANALYZE_TIMEOUT` | server | `3m` | Go duration limit for one Python analyzer process |
| `HARDEN_ANALYZE_LIMIT` | server | `2` | Maximum simultaneous analyses; excess requests receive HTTP 429 with `Retry-After: 5` |
| `HARDEN_FIND_TIMEOUT` | agent | `25` | Per-`find` timeout in seconds |
| `HARDEN_LLM_PROVIDER` | analyzer | `anthropic` unless only `OPENAI_API_KEY` is set | `anthropic` or `openai` |
| `HARDEN_MODEL` | analyzer | `claude-sonnet-4-5` for Anthropic, `gpt-5-mini` for OpenAI | LLM model id |
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
curl -H "X-Auth-Token: $HARDEN_UI_TOKEN" -X POST http://127.0.0.1:8000/analyze/$(hostname)
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
