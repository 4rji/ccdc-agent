#!/usr/bin/env python3
"""CCDC hardening tracker — receives agent reports, runs the LLM diagnosis,
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
            f"<a href='/analysis/{host}'>analysis</a> · "
            f"<form method='post' action='/analyze/{host}' style='display:inline'>"
            f"<button type='submit'>run analysis</button></form></td></tr>"
        )
    body = "".join(rows) or "<tr><td colspan=5>no reports yet</td></tr>"
    return f"""<!doctype html><meta charset=utf-8><title>CCDC Hardening Tracker</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:.5rem .7rem;text-align:left}}
th{{background:#f3f3f3}}a{{color:#0645ad}}code{{background:#f3f3f3;padding:1px 4px;border-radius:3px}}
button{{font:inherit;padding:1px 8px;cursor:pointer}}</style>
<h1>CCDC Hardening Tracker</h1>
<p>Reports received from team hosts. POST to
<code>/analyze/&lt;host&gt;</code> to run the LLM diagnosis.</p>
<table><tr><th>host</th><th>collected as</th><th>received (UTC)</th><th>analyzed</th><th>links</th></tr>
{body}</table>"""
