#!/usr/bin/env python3
"""CCDC hardening tracker - receives agent reports, runs the LLM diagnosis,
and shows team progress.

Run:
    pip install fastapi uvicorn anthropic openai
    HARDEN_TOKEN=secret ANTHROPIC_API_KEY=sk-... \
        uvicorn server:app --host 0.0.0.0 --port 8000

    # Or use OpenAI:
    HARDEN_TOKEN=secret HARDEN_LLM_PROVIDER=openai OPENAI_API_KEY=sk-... \
        uvicorn server:app --host 0.0.0.0 --port 8000
"""
import os
import json
import base64
import html
import datetime
import logging
import pathlib

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import HTMLResponse, PlainTextResponse

from analyzer import analyze_report, model_for, select_provider

AUTH_TOKEN = os.environ.get("HARDEN_TOKEN", "changeme-shared-secret")
DATA_DIR = pathlib.Path(os.environ.get("HARDEN_DATA", "./reports"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=os.environ.get("HARDEN_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("harden.server")

app = FastAPI(title="CCDC Hardening Tracker")

DASHBOARD_CSS = """
:root {
  color-scheme: light;
  --bg: #f6f7f2;
  --panel: #ffffff;
  --panel-soft: #f9faf7;
  --ink: #17211b;
  --muted: #667066;
  --line: #d9ded3;
  --accent: #245b45;
  --accent-strong: #174633;
  --warn: #9a5b00;
  --danger: #9f2f2f;
  --ok-bg: #e7f3ec;
  --warn-bg: #fff4db;
  --danger-bg: #fbe7e5;
  --info-bg: #e8f0f7;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 14px/1.45 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.shell {
  width: min(1180px, calc(100% - 32px));
  margin: 0 auto;
  padding: 28px 0 36px;
}
.topbar {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 22px;
}
.eyebrow {
  margin: 0 0 5px;
  color: var(--accent);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0;
  text-transform: uppercase;
}
h1 {
  margin: 0;
  font-size: clamp(30px, 5vw, 48px);
  line-height: 1;
  letter-spacing: 0;
}
.runtime {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  color: var(--muted);
  font-size: 12px;
}
.runtime span,
.badge {
  display: inline-flex;
  align-items: center;
  min-height: 26px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--panel);
  padding: 3px 9px;
  white-space: nowrap;
}
.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 18px;
}
.metric {
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  padding: 14px 16px;
}
.metric span {
  display: block;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}
.metric strong {
  display: block;
  margin-top: 6px;
  font-size: 30px;
  line-height: 1;
}
.table-panel {
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
}
.table-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  border-bottom: 1px solid var(--line);
  background: var(--panel-soft);
  padding: 13px 16px;
}
.table-heading h2 {
  margin: 0;
  font-size: 16px;
  letter-spacing: 0;
}
.table-heading span {
  color: var(--muted);
  font-size: 12px;
}
.table-scroll {
  overflow-x: auto;
}
table {
  width: 100%;
  min-width: 820px;
  border-collapse: collapse;
}
th,
td {
  border-bottom: 1px solid var(--line);
  padding: 12px 14px;
  text-align: left;
  vertical-align: middle;
}
th {
  background: #fbfcf8;
  color: #465047;
  font-size: 12px;
  font-weight: 800;
  text-transform: uppercase;
}
tr:last-child td {
  border-bottom: 0;
}
tbody tr:hover {
  background: #fcf8ed;
}
.host strong {
  display: block;
  font-size: 15px;
}
.host span {
  display: block;
  color: var(--muted);
  font-size: 12px;
  margin-top: 2px;
}
.badge.ok {
  border-color: #b7d8c5;
  background: var(--ok-bg);
  color: #1f6842;
}
.badge.pending {
  border-color: #efd08d;
  background: var(--warn-bg);
  color: var(--warn);
}
.badge.root {
  border-color: #b9d5c6;
  background: var(--ok-bg);
  color: var(--accent-strong);
}
.badge.limited {
  border-color: #edc7c1;
  background: var(--danger-bg);
  color: var(--danger);
}
.actions {
  display: flex;
  align-items: center;
  gap: 7px;
  flex-wrap: wrap;
}
.button,
button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 32px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--panel);
  color: var(--ink);
  padding: 5px 10px;
  font: inherit;
  font-weight: 700;
  text-decoration: none;
  cursor: pointer;
}
button.primary {
  border-color: var(--accent);
  background: var(--accent);
  color: #fff;
}
.button:hover,
button:hover {
  border-color: var(--accent);
}
.empty {
  padding: 34px 16px;
  color: var(--muted);
  text-align: center;
}
@media (max-width: 760px) {
  .shell {
    width: min(100% - 20px, 1180px);
    padding-top: 18px;
  }
  .topbar {
    align-items: flex-start;
    flex-direction: column;
  }
  .runtime {
    justify-content: flex-start;
  }
  .metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
"""


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


def load_dashboard_reports():
    reports = []
    for f in sorted(DATA_DIR.glob("*.json")):
        try:
            payload = json.loads(f.read_text())
        except Exception:
            logger.warning("skipping unreadable report path=%s", f)
            continue
        host = payload.get("hostname") or f.stem
        decoded = payload.get("_decoded", {})
        reports.append({
            "host": host,
            "host_id": safe(host),
            "collected_as": payload.get("collected_as", "?"),
            "received": payload.get("_received", "?"),
            "timestamp": payload.get("timestamp", "?"),
            "sections": len(decoded),
            "analyzed": analysis_path(host).exists(),
        })
    return sorted(reports, key=lambda item: item["received"], reverse=True)


@app.on_event("startup")
def log_startup():
    provider = select_provider()
    logger.info("server starting data_dir=%s auth_token_set=%s", DATA_DIR.resolve(), bool(AUTH_TOKEN))
    logger.info(
        "llm provider=%s model=%s anthropic_key_set=%s openai_key_set=%s",
        provider,
        model_for(provider),
        bool(os.environ.get("ANTHROPIC_API_KEY")),
        bool(os.environ.get("OPENAI_API_KEY")),
    )


@app.post("/report")
async def receive_report(request: Request, x_auth_token: str = Header(default="")):
    if x_auth_token != AUTH_TOKEN:
        logger.warning(
            "rejected report from %s: bad token header_present=%s",
            request.client.host if request.client else "?",
            bool(x_auth_token),
        )
        raise HTTPException(status_code=401, detail="bad token")
    payload = await request.json()
    payload["_decoded"] = decode_checks(payload.get("checks", {}))
    payload["_received"] = datetime.datetime.utcnow().isoformat() + "Z"
    payload.pop("checks", None)  # discard the base64 blob, keep the decoded data
    host = payload.get("hostname", "unknown")
    decoded = payload.get("_decoded", {})
    path = report_path(host)
    path.write_text(json.dumps(payload, indent=2))
    logger.info(
        "received report host=%s from=%s collected_as=%s sections=%s path=%s",
        host,
        request.client.host if request.client else "?",
        payload.get("collected_as", "?"),
        ",".join(decoded.keys()) or "-",
        path,
    )
    return {"status": "ok", "host": payload.get("hostname")}


@app.post("/analyze/{host}")
def analyze(host: str):
    logger.info("analysis requested host=%s", host)
    p = report_path(host)
    if not p.exists():
        logger.warning("analysis failed host=%s reason=report_not_found path=%s", host, p)
        raise HTTPException(404, "no report for that host")
    payload = json.loads(p.read_text())
    provider = select_provider()
    logger.info(
        "analysis starting host=%s provider=%s model=%s report_path=%s",
        host,
        provider,
        model_for(provider),
        p,
    )
    result = analyze_report(payload)
    out = analysis_path(host)
    out.write_text(result)
    if result.startswith("[analyzer]"):
        logger.error("analysis returned analyzer error host=%s message=%s", host, result.splitlines()[0])
    else:
        logger.info("analysis completed host=%s bytes=%d path=%s", host, len(result), out)
    return PlainTextResponse(result)


@app.get("/analysis/{host}", response_class=PlainTextResponse)
def get_analysis(host: str):
    p = analysis_path(host)
    if p.exists():
        logger.info("served analysis host=%s path=%s", host, p)
        return p.read_text()
    logger.info("analysis not found host=%s path=%s", host, p)
    return f"no analysis yet - POST /analyze/{safe(host)}"


@app.get("/report/{host}", response_class=PlainTextResponse)
def get_report(host: str):
    p = report_path(host)
    if not p.exists():
        logger.warning("report not found host=%s path=%s", host, p)
        raise HTTPException(404, "no report")
    logger.info("served report host=%s path=%s", host, p)
    dec = json.loads(p.read_text()).get("_decoded", {})
    return "\n".join(f"===== {k.upper()} =====\n{v}\n" for k, v in dec.items())


@app.get("/", response_class=HTMLResponse)
def dashboard():
    reports = load_dashboard_reports()
    total = len(reports)
    analyzed_count = sum(1 for report in reports if report["analyzed"])
    root_count = sum(1 for report in reports if report["collected_as"] == "root")
    pending_count = total - analyzed_count
    provider = select_provider()

    rows = []
    for report in reports:
        host = html.escape(report["host"])
        host_id = html.escape(report["host_id"])
        who = html.escape(report["collected_as"])
        received = html.escape(report["received"])
        timestamp = html.escape(report["timestamp"])
        sections = report["sections"]
        status_class = "ok" if report["analyzed"] else "pending"
        status_text = "Analyzed" if report["analyzed"] else "Pending"
        identity_class = "root" if report["collected_as"] == "root" else "limited"
        identity_text = "Root" if report["collected_as"] == "root" else "Limited"
        rows.append(
            "<tr>"
            f"<td class='host'><strong>{host}</strong><span>Collected: {timestamp}</span></td>"
            f"<td><span class='badge {identity_class}'>{identity_text}</span> <span>{who}</span></td>"
            f"<td>{received}</td>"
            f"<td><span class='badge {status_class}'>{status_text}</span></td>"
            f"<td>{sections}</td>"
            "<td><div class='actions'>"
            f"<a class='button' href='/report/{host_id}'>Report</a>"
            f"<a class='button' href='/analysis/{host_id}'>Analysis</a>"
            f"<form method='post' action='/analyze/{host_id}'>"
            "<button class='primary' type='submit'>Run</button></form>"
            "</div></td>"
            "</tr>"
        )
    body = "".join(rows) or "<tr><td class='empty' colspan='6'>No host reports yet</td></tr>"
    model = html.escape(model_for(provider) or "not configured")
    provider_label = html.escape(provider)
    data_dir = html.escape(str(DATA_DIR))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CCDC Hardening Tracker</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div>
        <p class="eyebrow">Blue Team Operations</p>
        <h1>CCDC Hardening Tracker</h1>
      </div>
      <div class="runtime" aria-label="Runtime configuration">
        <span>Provider: {provider_label}</span>
        <span>Model: {model}</span>
        <span>Data: {data_dir}</span>
      </div>
    </header>

    <section class="metrics" aria-label="Report summary">
      <div class="metric"><span>Hosts</span><strong>{total}</strong></div>
      <div class="metric"><span>Analyzed</span><strong>{analyzed_count}</strong></div>
      <div class="metric"><span>Pending</span><strong>{pending_count}</strong></div>
      <div class="metric"><span>Root Reports</span><strong>{root_count}</strong></div>
    </section>

    <section class="table-panel" aria-label="Host reports">
      <div class="table-heading">
        <h2>Host Reports</h2>
        <span>{total} total</span>
      </div>
      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Identity</th>
              <th>Received UTC</th>
              <th>Status</th>
              <th>Sections</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>{body}</tbody>
        </table>
      </div>
    </section>
  </main>
</body>
</html>"""
