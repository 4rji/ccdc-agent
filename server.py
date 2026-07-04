#!/usr/bin/env python3
"""CCDC hardening tracker — recibe reportes del agente, corre el diagnostico
con LLM y muestra el avance del equipo.

Correr:
    pip install fastapi uvicorn anthropic openai
    HARDEN_TOKEN=secreto ANTHROPIC_API_KEY=sk-... \
        uvicorn server:app --host 0.0.0.0 --port 8000

    # O usa OpenAI:
    HARDEN_TOKEN=secreto HARDEN_LLM_PROVIDER=openai OPENAI_API_KEY=sk-... \
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
    payload.pop("checks", None)  # descarta el blob base64, conserva lo decodificado
    report_path(payload.get("hostname", "unknown")).write_text(json.dumps(payload, indent=2))
    return {"status": "ok", "host": payload.get("hostname")}


@app.post("/analyze/{host}")
def analyze(host: str):
    p = report_path(host)
    if not p.exists():
        raise HTTPException(404, "no hay reporte para ese host")
    payload = json.loads(p.read_text())
    result = analyze_report(payload)
    analysis_path(host).write_text(result)
    return PlainTextResponse(result)


@app.get("/analysis/{host}", response_class=PlainTextResponse)
def get_analysis(host: str):
    p = analysis_path(host)
    return p.read_text() if p.exists() else f"sin analisis aun — haz POST /analyze/{safe(host)}"


@app.get("/report/{host}", response_class=PlainTextResponse)
def get_report(host: str):
    p = report_path(host)
    if not p.exists():
        raise HTTPException(404, "no hay reporte")
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
        analyzed = "si" if analysis_path(p.get("hostname", "?")).exists() else "no"
        rows.append(
            f"<tr><td>{host}</td><td>{who}</td><td>{recv}</td><td>{analyzed}</td>"
            f"<td><a href='/report/{host}'>reporte</a> · "
            f"<a href='/analysis/{host}'>analisis</a></td></tr>"
        )
    body = "".join(rows) or "<tr><td colspan=5>aun no hay reportes</td></tr>"
    return f"""<!doctype html><meta charset=utf-8><title>CCDC Hardening Tracker</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:.5rem .7rem;text-align:left}}
th{{background:#f3f3f3}}a{{color:#0645ad}}code{{background:#f3f3f3;padding:1px 4px;border-radius:3px}}</style>
<h1>CCDC Hardening Tracker</h1>
<p>Reportes recibidos de los hosts del equipo. Haz POST a
<code>/analyze/&lt;host&gt;</code> para correr el diagnostico con LLM.</p>
<table><tr><th>host</th><th>recolectado como</th><th>recibido (UTC)</th><th>analizado</th><th>links</th></tr>
{body}</table>"""
