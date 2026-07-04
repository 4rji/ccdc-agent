# CCDC Hardening Tracker

A small **agent + server + LLM** toolkit to track a blue team's Linux hardening
progress during a CCDC-style competition. Each host runs a collector script that
dumps its security-relevant state (services, processes, scheduled tasks,
permissions, users, network, firewall, persistence spots) and POSTs it to a
central server. The server stores one report per host and, on demand, asks an
LLM to produce a diagnosis: **what's still misconfigured, what's running, and
what looks like a red-team artifact** — with copy-paste fix commands.

The agent only **reads** state; it never changes anything. Password hashes are
never exported — only their status (`set` / `locked` / `EMPTY!`).

```
[ host 1 ] --+
[ host 2 ] --+-->  POST /report  -->  server.py  --/analyze-->  LLM  -->  report
[ host 3 ] --+        (stores one JSON per host)                       + dashboard at /
```

## Requirements

- **Server:** Python 3.9+, `pip`, and an LLM API key (Anthropic by default).
- **Agents:** `bash`, `base64`, and `curl` (or `wget`). All standard on Linux.
  Run the agent as **root** for full coverage (shadow status, every user's
  crontab and SSH keys).

## Project layout

Three files, no framework beyond FastAPI:

```
hardening_agent.sh   # runs on each defended host: collects state + phones home
server.py            # FastAPI: receives reports, serves dashboard, triggers analysis
analyzer.py          # builds the prompt and calls the LLM
```

## Quick start

**1. Create the three files** (full source in the next section) and keep them in
the same directory.

**2. Start the server:**

```bash
pip install fastapi uvicorn anthropic
export HARDEN_TOKEN="a-long-shared-secret"     # agents must send the same token
export ANTHROPIC_API_KEY="sk-ant-..."
export HARDEN_MODEL="claude-sonnet-4-5"        # set to a model you can access
uvicorn server:app --host 0.0.0.0 --port 8000
```

Open `http://SERVER:8000/` for the dashboard.

**3. Run the agent on each host** (as root for full coverage):

```bash
sudo HARDEN_SERVER="http://SERVER:8000/report" \
     HARDEN_TOKEN="a-long-shared-secret" \
     ./hardening_agent.sh send
```

Try it locally first, without sending anything:

```bash
sudo ./hardening_agent.sh text     # human-readable dump
sudo ./hardening_agent.sh local    # raw JSON
```

**4. Get a diagnosis** for a host (its hostname becomes its id):

```bash
curl -X POST http://SERVER:8000/analyze/web01     # returns the report as text
```

## Full source

Copy each block into a file with the matching name.

### `hardening_agent.sh`

```bash
#!/usr/bin/env bash
# hardening_agent.sh — CCDC Linux hardening state collector + phone-home agent
#
# Collects services, processes, scheduled tasks, permissions, users, network,
# firewall and persistence spots, then PRINTS or SENDS a JSON report to the
# central server for LLM diagnosis.
#
#   ./hardening_agent.sh text     # human-readable dump to stdout
#   ./hardening_agent.sh local    # JSON to stdout (no network)
#   ./hardening_agent.sh send      # POST JSON to $HARDEN_SERVER  (default)
#
# Config via environment variables:
#   HARDEN_SERVER=http://10.0.0.5:8000/report
#   HARDEN_TOKEN=shared-secret
#
# Run as root for full coverage (shadow status, all crontabs, all
# authorized_keys). Password hashes are NOT exported, only their status.

set -uo pipefail

SERVER_URL="${HARDEN_SERVER:-http://127.0.0.1:8000/report}"
AUTH_TOKEN="${HARDEN_TOKEN:-changeme-shared-secret}"
MODE="${1:-send}"
FIND_TIMEOUT="${HARDEN_FIND_TIMEOUT:-25}"
CAP=200

b64()  { printf '%s' "${1:-}" | base64 | tr -d '\n'; }
jesc() { printf '"%s"' "$(printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g')"; }
h()    { printf '\n## %s\n' "$1"; }              # sub-header inside a section
tmo()  { timeout "$FIND_TIMEOUT" "$@" 2>/dev/null || true; }

collect_system() {
  h "Kernel / arch";     uname -a 2>/dev/null
  h "OS release";        cat /etc/os-release 2>/dev/null
  h "Uptime / load";     uptime 2>/dev/null
  h "Last boot";         who -b 2>/dev/null
  h "Current identity";  id 2>/dev/null
}

collect_users() {
  h "Accounts (name uid gid shell)"
  awk -F: '{print $1, "uid="$3, "gid="$4, "shell="$7}' /etc/passwd 2>/dev/null
  h "UID 0 accounts (should be ONLY root)"
  awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null
  h "Accounts with an interactive shell"
  awk -F: '$7 ~ /(bash|sh|zsh|ksh|fish)$/{print $1" -> "$7}' /etc/passwd 2>/dev/null
  h "Password status (EMPTY!/locked/set — hashes NOT exported)"
  if [ -r /etc/shadow ]; then
    awk -F: '{s=$2; st=(s==""?"EMPTY!":(s ~ /^[!*]/?"locked":"set")); print $1": "st}' /etc/shadow 2>/dev/null
  else
    echo "(need root to read /etc/shadow)"
  fi
  h "Sudoers / privileged groups"
  grep -Ev '^\s*#|^\s*$' /etc/sudoers 2>/dev/null
  cat /etc/sudoers.d/* 2>/dev/null | grep -Ev '^\s*#|^\s*$'
  getent group sudo wheel admin 2>/dev/null
  h "Recent successful logins"; last -n 15 2>/dev/null
  h "Recent FAILED logins";     lastb -n 15 2>/dev/null
}

collect_processes() {
  h "Full process list"
  ps auxww 2>/dev/null
  h "Processes launched from tmp/shm/var-tmp (suspicious)"
  ps auxww 2>/dev/null | grep -E '/tmp/|/dev/shm/|/var/tmp/' | grep -v grep
  h "Running deleted binaries (possible in-memory malware)"
  ls -l /proc/*/exe 2>/dev/null | grep -i '(deleted)'
  h "Shell/tunnel tools currently running"
  ps auxww 2>/dev/null | grep -E '\b(nc|ncat|socat|/bin/bash -i|python.*socket|perl.*socket|msf|meterpreter)\b' | grep -v grep
}

collect_network() {
  h "Listening sockets (with process)"
  ss -tulpnw 2>/dev/null || netstat -tulpnw 2>/dev/null
  h "Established connections"
  ss -tupnw state established 2>/dev/null || { netstat -tupnw 2>/dev/null | grep ESTAB; }
}

collect_services() {
  h "Running services"
  systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
    || service --status-all 2>/dev/null
  h "Enabled-at-boot services"
  systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null
  h "Failed units"
  systemctl --failed --no-pager --no-legend 2>/dev/null
}

collect_scheduled() {
  h "System crontab"; cat /etc/crontab 2>/dev/null
  h "cron.d / periodic dirs"
  ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
  cat /etc/cron.d/* 2>/dev/null
  h "Per-user crontabs"
  for u in $(cut -f1 -d: /etc/passwd 2>/dev/null); do
    out="$(crontab -u "$u" -l 2>/dev/null)"
    [ -n "$out" ] && { echo "### $u"; echo "$out"; }
  done
  h "systemd timers"; systemctl list-timers --all --no-pager --no-legend 2>/dev/null
  h "at jobs"; atq 2>/dev/null
  h "rc.local"; cat /etc/rc.local 2>/dev/null
}

collect_permissions() {
  h "SUID binaries";  tmo find / -xdev -perm -4000 -type f | head -"$CAP"
  h "SGID binaries";  tmo find / -xdev -perm -2000 -type f | head -"$CAP"
  h "World-writable files"; tmo find / -xdev -type f -perm -0002 | head -"$CAP"
  h "World-writable dirs without sticky bit"; tmo find / -xdev -type d -perm -0002 ! -perm -1000 | head -50
  h "Files with no owner (nouser/nogroup)"; tmo find / -xdev \( -nouser -o -nogroup \) | head -50
}

collect_ssh() {
  h "sshd_config (effective lines)"
  grep -Ev '^\s*#|^\s*$' /etc/ssh/sshd_config 2>/dev/null
  h "authorized_keys per user"
  for home in /root /home/*; do
    [ -f "$home/.ssh/authorized_keys" ] && { echo "### $home"; cat "$home/.ssh/authorized_keys" 2>/dev/null; }
  done
}

collect_firewall() {
  h "iptables rules"; iptables -S 2>/dev/null
  h "nftables ruleset"; nft list ruleset 2>/dev/null
  h "ufw status"; ufw status verbose 2>/dev/null
  h "firewalld"; firewall-cmd --list-all 2>/dev/null
}

collect_persistence() {
  h "ld.so.preload (should be empty/absent)"; cat /etc/ld.so.preload 2>/dev/null
  h "init.d scripts"; ls -la /etc/init.d 2>/dev/null
  h "profile.d scripts"; ls -la /etc/profile.d 2>/dev/null
  h "systemd system units"; ls -la /etc/systemd/system 2>/dev/null
  h "Shell rc files (mtime)"
  for home in /root /home/*; do
    ls -la "$home/.bashrc" "$home/.bash_profile" "$home/.profile" 2>/dev/null
  done
  h "Recently modified system binaries (<7 days)"
  tmo find /usr/bin /usr/sbin /bin /sbin -mtime -7 -type f | head -50
}

# ---- collect everything ----
declare -A CHECKS
CHECKS[system]="$(collect_system)"
CHECKS[users]="$(collect_users)"
CHECKS[processes]="$(collect_processes)"
CHECKS[network]="$(collect_network)"
CHECKS[services]="$(collect_services)"
CHECKS[scheduled]="$(collect_scheduled)"
CHECKS[permissions]="$(collect_permissions)"
CHECKS[ssh]="$(collect_ssh)"
CHECKS[firewall]="$(collect_firewall)"
CHECKS[persistence]="$(collect_persistence)"

ORDER=(system users processes network services scheduled permissions ssh firewall persistence)
HOST="$(hostname 2>/dev/null || echo unknown)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
WHO="$(id -un 2>/dev/null || echo unknown)"

build_json() {
  printf '{'
  printf '"hostname":%s,' "$(jesc "$HOST")"
  printf '"timestamp":"%s",' "$TS"
  printf '"collected_as":%s,' "$(jesc "$WHO")"
  printf '"checks":{'
  local first=1
  for k in "${ORDER[@]}"; do
    [ $first -eq 0 ] && printf ','
    first=0
    printf '"%s":"%s"' "$k" "$(b64 "${CHECKS[$k]:-}")"
  done
  printf '}}'
}

case "$MODE" in
  text)
    for k in "${ORDER[@]}"; do
      printf '\n===== %s =====\n' "${k^^}"
      printf '%s\n' "${CHECKS[$k]}"
    done
    ;;
  local)
    build_json; echo
    ;;
  send)
    payload="$(build_json)"
    echo "[*] Host=$HOST as=$WHO bytes=${#payload} -> $SERVER_URL"
    if command -v curl >/dev/null 2>&1; then
      printf '%s' "$payload" | curl -sS -X POST "$SERVER_URL" \
        -H "Content-Type: application/json" -H "X-Auth-Token: $AUTH_TOKEN" \
        --data-binary @- && echo && echo "[+] sent" || echo "[!] send failed"
    elif command -v wget >/dev/null 2>&1; then
      printf '%s' "$payload" | wget -q -O- --header="Content-Type: application/json" \
        --header="X-Auth-Token: $AUTH_TOKEN" --post-data="$payload" "$SERVER_URL" \
        && echo "[+] sent (wget)" || echo "[!] send failed"
    else
      echo "[!] no curl or wget found; use 'local' mode and pipe the JSON yourself"
    fi
    ;;
  *)
    echo "usage: $0 {text|local|send}"; exit 1;;
esac
```

### `server.py`

```python
#!/usr/bin/env python3
"""CCDC hardening tracker — receives agent reports, runs the LLM diagnosis,
and shows team progress.

Run:
    pip install fastapi uvicorn anthropic
    HARDEN_TOKEN=secret ANTHROPIC_API_KEY=sk-... \
        uvicorn server:app --host 0.0.0.0 --port 8000
"""
import os
import json
import base64
import html
import datetime
import pathlib

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import HTMLResponse, PlainTextResponse

from analyzer import analyze_report

AUTH_TOKEN = os.environ.get("HARDEN_TOKEN", "changeme-shared-secret")
DATA_DIR = pathlib.Path(os.environ.get("HARDEN_DATA", "./reports"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="CCDC Hardening Tracker")


def safe(name: str) -> str:
    return "".join(c for c in (name or "unknown") if c.isalnum() or c in "-._") or "unknown"


def decode_checks(checks: dict) -> dict:
    out = {}
    for k, v in (checks or {}).items():
        try:
            out[k] = base64.b64decode(v).decode("utf-8", "replace")
        except Exception:
            out[k] = "<decode error>"
    return out


def report_path(host):
    return DATA_DIR / f"{safe(host)}.json"


def analysis_path(host):
    return DATA_DIR / f"{safe(host)}.analysis.txt"


@app.post("/report")
async def receive_report(request: Request, x_auth_token: str = Header(default="")):
    if x_auth_token != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="bad token")
    payload = await request.json()
    payload["_decoded"] = decode_checks(payload.get("checks", {}))
    payload["_received"] = datetime.datetime.utcnow().isoformat() + "Z"
    payload.pop("checks", None)  # drop the base64 blob, keep the decoded text
    report_path(payload.get("hostname", "unknown")).write_text(json.dumps(payload, indent=2))
    return {"status": "ok", "host": payload.get("hostname")}


@app.post("/analyze/{host}")
def analyze(host: str):
    p = report_path(host)
    if not p.exists():
        raise HTTPException(404, "no report for that host")
    payload = json.loads(p.read_text())
    result = analyze_report(payload)
    analysis_path(host).write_text(result)
    return PlainTextResponse(result)


@app.get("/analysis/{host}", response_class=PlainTextResponse)
def get_analysis(host: str):
    p = analysis_path(host)
    return p.read_text() if p.exists() else f"no analysis yet — POST /analyze/{safe(host)} first"


@app.get("/report/{host}", response_class=PlainTextResponse)
def get_report(host: str):
    p = report_path(host)
    if not p.exists():
        raise HTTPException(404, "no report")
    dec = json.loads(p.read_text()).get("_decoded", {})
    return "\n".join(f"===== {k.upper()} =====\n{v}\n" for k, v in dec.items())


@app.get("/", response_class=HTMLResponse)
def dashboard():
    rows = []
    for f in sorted(DATA_DIR.glob("*.json")):
        try:
            p = json.loads(f.read_text())
        except Exception:
            continue
        host = html.escape(p.get("hostname", "?"))
        who = html.escape(p.get("collected_as", "?"))
        recv = html.escape(p.get("_received", "?"))
        analyzed = "yes" if analysis_path(p.get("hostname", "?")).exists() else "no"
        rows.append(
            f"<tr><td>{host}</td><td>{who}</td><td>{recv}</td><td>{analyzed}</td>"
            f"<td><a href='/report/{host}'>report</a> · "
            f"<a href='/analysis/{host}'>analysis</a></td></tr>"
        )
    body = "".join(rows) or "<tr><td colspan=5>no reports yet</td></tr>"
    return f"""<!doctype html><meta charset=utf-8><title>CCDC Hardening Tracker</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:.5rem .7rem;text-align:left}}
th{{background:#f3f3f3}}a{{color:#0645ad}}code{{background:#f3f3f3;padding:1px 4px;border-radius:3px}}</style>
<h1>CCDC Hardening Tracker</h1>
<p>Reports received from team hosts. POST
<code>/analyze/&lt;host&gt;</code> to run the LLM diagnosis.</p>
<table><tr><th>host</th><th>collected as</th><th>received (UTC)</th><th>analyzed</th><th>links</th></tr>
{body}</table>"""
```

### `analyzer.py`

```python
#!/usr/bin/env python3
"""LLM diagnosis of a hardening report collected by the agent."""
import os
import textwrap

# IMPORTANT: set this to a model YOU have access to with your API key.
MODEL = os.environ.get("HARDEN_MODEL", "claude-sonnet-4-5")
MAX_REPORT_CHARS = int(os.environ.get("HARDEN_MAX_CHARS", "120000"))

SYSTEM_PROMPT = textwrap.dedent("""\
    You are a senior blue-team operator auditing ONE host during a CCDC-style
    cyber defense competition. Assume an active red team already has footholds
    and plants persistence: extra users, unauthorized SSH keys, cron and
    systemd-timer backdoors, SUID root shells, reverse-shell listeners, modified
    rc/profile files, and ld.so.preload hijacks. The blue team is hardening the
    box against the clock.

    You are given the raw output of an automated collection script. Analyze it
    and produce a concrete, prioritized report. Rules:
    - Cite the EXACT evidence line from the report when you flag something.
    - Give copy-paste remediation commands.
    - Distinguish "likely red-team artifact / compromise" from "hardening gap".
    - Do not invent findings the data does not support. If a section is empty or
      says it needs root, say so.
    - Be terse. No preamble, no filler.
    """)

USER_TEMPLATE = textwrap.dedent("""\
    HOST: {host}
    COLLECTED_AS: {who}   (if not root, coverage is partial)
    TIMESTAMP: {ts}

    Produce these sections in order:

    1. HARDENING SCORE: X/100 — one-line justification.
    2. LIKELY COMPROMISE / RED-TEAM ARTIFACTS — for each: evidence line, why it
       is suspicious, fix command.
    3. HARDENING GAPS (what they still need to do) — SSH (root login,
       PasswordAuthentication), firewall state, empty-password or duplicate UID 0
       accounts, unnecessary listening services, world-writable/SUID anomalies,
       pending updates. Each with a fix command.
    4. SUSPICIOUS PROCESSES / SERVICES / SCHEDULED TASKS — short table:
       item | evidence | action.
    5. DO-THIS-NOW CHECKLIST — ordered, highest impact first.

    ===== RAW COLLECTION REPORT =====
    {report}
    """)


def build_report_text(decoded: dict) -> str:
    parts = []
    for k, v in decoded.items():
        parts.append(f"===== {k.upper()} =====\n{(v or '').strip()}\n")
    return "\n".join(parts)


def analyze_report(payload: dict) -> str:
    decoded = payload.get("_decoded", {})
    report = build_report_text(decoded)
    if len(report) > MAX_REPORT_CHARS:
        report = report[:MAX_REPORT_CHARS] + "\n...[truncated]..."

    prompt = USER_TEMPLATE.format(
        host=payload.get("hostname", "?"),
        who=payload.get("collected_as", "?"),
        ts=payload.get("timestamp", "?"),
        report=report,
    )

    try:
        from anthropic import Anthropic
    except ImportError:
        return ("[analyzer] the `anthropic` library is missing. Run "
                "`pip install anthropic` and export ANTHROPIC_API_KEY.")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        return "[analyzer] ANTHROPIC_API_KEY is not set."

    client = Anthropic()
    try:
        msg = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        return (f"[analyzer] API call failed: {e}\n"
                f"Check that HARDEN_MODEL ('{MODEL}') is a model you can access.")

    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


# ---- swap to another provider (OpenAI example) ----
# Replace the analyze_report(...) body with this if you prefer OpenAI:
#   from openai import OpenAI
#   client = OpenAI()
#   r = client.chat.completions.create(
#       model=os.environ.get("HARDEN_MODEL", "gpt-4o"),
#       messages=[{"role": "system", "content": SYSTEM_PROMPT},
#                 {"role": "user", "content": prompt}])
#   return r.choices[0].message.content
```

## Automating the agent ("run it after the session")

Install the script once, then use cron or a systemd timer so it phones home on a
schedule.

```bash
sudo cp hardening_agent.sh /usr/local/bin/hardening_agent.sh
sudo chmod +x /usr/local/bin/hardening_agent.sh
```

### Option A — cron (every 10 minutes)

```bash
echo '*/10 * * * * root HARDEN_SERVER=http://SERVER:8000/report HARDEN_TOKEN=a-long-shared-secret /usr/local/bin/hardening_agent.sh send >/var/log/harden-agent.log 2>&1' \
  | sudo tee /etc/cron.d/hardening-agent
```

### Option B — systemd timer (installed agent)

`/etc/systemd/system/hardening-agent.service`:

```ini
[Unit]
Description=CCDC hardening collector

[Service]
Type=oneshot
Environment=HARDEN_SERVER=http://SERVER:8000/report
Environment=HARDEN_TOKEN=a-long-shared-secret
ExecStart=/usr/local/bin/hardening_agent.sh send
```

`/etc/systemd/system/hardening-agent.timer`:

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

## HTTP API

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/report` | Agent submits a report (needs `X-Auth-Token` header) |
| POST | `/analyze/<host>` | Run the LLM diagnosis for a host; returns text |
| GET | `/analysis/<host>` | Last saved diagnosis for a host |
| GET | `/report/<host>` | Decoded raw collection report for a host |
| GET | `/` | Dashboard listing all hosts |

## How it works

- The agent runs one `collect_*` function per category and concatenates their
  output into labeled sections.
- Each section is **base64-encoded** inside the JSON payload, so raw command
  output (quotes, newlines, control chars) can't break parsing. The server
  decodes on receipt and drops the encoded blob.
- Reports are stored as `reports/<host>.json`; diagnoses as
  `reports/<host>.analysis.txt`.
- Only password **status** is collected, never hashes — safer to centralize and
  enough for the diagnosis.

## Configuration (environment variables)

| Variable | Used by | Default | Meaning |
|----------|---------|---------|---------|
| `HARDEN_SERVER` | agent | `http://127.0.0.1:8000/report` | Where to POST reports |
| `HARDEN_TOKEN` | agent + server | `changeme-shared-secret` | Shared token; must match |
| `HARDEN_FIND_TIMEOUT` | agent | `25` | Per-`find` timeout, seconds |
| `HARDEN_DATA` | server | `./reports` | Where reports are stored |
| `HARDEN_MODEL` | analyzer | `claude-sonnet-4-5` | LLM model id (use one you can access) |
| `HARDEN_MAX_CHARS` | analyzer | `120000` | Truncate very large reports before sending |
| `ANTHROPIC_API_KEY` | analyzer | — | Your API key |

## Security notes (matters when a red team is active)

- **Use TLS** (put the server behind nginx/caddy with HTTPS) or keep it strictly
  on the internal scoring network. Reports contain SSH keys, config, and
  listeners.
- `HARDEN_TOKEN` only stops casual spam — don't treat it as strong auth.
- The server centralizes data from every box; if it's compromised it's a
  goldmine. Isolate it and don't leave API keys lying around longer than needed.
- The agent only reads state. Apply fixes yourself using the commands the
  diagnosis suggests.

## Changing the LLM provider or output language

`analyzer.py` targets the Anthropic API. To use OpenAI instead, swap the client
block (a commented example sits at the bottom of the file). The prompts are in
English, so the diagnosis comes back in English — edit `SYSTEM_PROMPT` /
`USER_TEMPLATE` in `analyzer.py` if you want another language.

## Easy extensions

- **Baseline diff:** save the first clean report and compare later ones so
  changes stand out (that's usually red-team activity).
- **Scoreboard:** a `/scoreboard` endpoint that sorts hosts by the LLM's score.
- **Fold in existing tools:** add `lynis audit system --quick` and `chkrootkit`
  output as extra sections in the agent.
- **Alerts:** fire a Slack/Discord webhook when a new UID 0 account, an `EMPTY!`
  password, or a new listener appears.
