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
import re

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

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
.analysis-top {
  align-items: flex-start;
  margin-bottom: 16px;
}
.back-link {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  margin-bottom: 10px;
  color: var(--accent);
  font-weight: 800;
  text-decoration: none;
}
.back-link:hover {
  color: var(--accent-strong);
}
.analysis-summary {
  display: grid;
  grid-template-columns: minmax(240px, 330px) minmax(0, 1fr);
  gap: 14px;
  margin-bottom: 18px;
}
.score-panel,
.summary-panel,
.analysis-card,
.side-panel {
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
}
.score-panel {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  gap: 14px;
  padding: 16px;
}
.score-ring {
  display: grid;
  place-items: center;
  width: 96px;
  height: 96px;
  border: 9px solid var(--line);
  border-radius: 50%;
  background: #fff;
}
.score-ring.ok {
  border-color: #78b58e;
}
.score-ring.warn {
  border-color: #d8a83f;
}
.score-ring.danger {
  border-color: #cf6d62;
}
.score-ring.neutral {
  border-color: #aab2aa;
}
.score-ring strong {
  font-size: 28px;
  line-height: 1;
}
.score-ring span {
  color: var(--muted);
  font-size: 11px;
  font-weight: 800;
}
.score-copy span,
.summary-panel span,
.side-panel span {
  color: var(--muted);
  font-size: 12px;
  font-weight: 800;
  text-transform: uppercase;
}
.score-copy strong {
  display: block;
  margin-top: 5px;
  font-size: 18px;
}
.score-copy p,
.summary-panel p {
  margin: 7px 0 0;
  color: var(--muted);
}
.summary-panel {
  padding: 16px;
}
.section-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 13px;
}
.section-pills a {
  display: inline-flex;
  align-items: center;
  min-height: 28px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--panel-soft);
  color: var(--ink);
  padding: 3px 10px;
  font-size: 12px;
  font-weight: 800;
  text-decoration: none;
}
.section-pills a:hover {
  border-color: var(--accent);
}
.analysis-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 280px;
  align-items: start;
  gap: 16px;
}
.analysis-stack {
  display: grid;
  gap: 12px;
}
.analysis-card {
  overflow: hidden;
}
.analysis-card header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  border-bottom: 1px solid var(--line);
  background: var(--panel-soft);
  padding: 12px 15px;
}
.analysis-card h2 {
  margin: 0;
  font-size: 16px;
  letter-spacing: 0;
}
.analysis-card .count {
  color: var(--muted);
  font-size: 12px;
  white-space: nowrap;
}
.analysis-content {
  padding: 14px 15px 16px;
}
.analysis-content p {
  margin: 0 0 10px;
}
.analysis-content p:last-child,
.analysis-content ul:last-child,
.analysis-content ol:last-child,
.analysis-content table:last-child {
  margin-bottom: 0;
}
.analysis-content ul,
.analysis-content ol {
  margin: 0 0 12px;
  padding-left: 22px;
}
.analysis-content li {
  margin: 5px 0;
}
.analysis-content code {
  border: 1px solid var(--line);
  border-radius: 5px;
  background: #f3f5f0;
  padding: 1px 5px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
.analysis-content strong {
  color: #111812;
}
.analysis-content .table-scroll {
  margin: 2px 0 13px;
  border: 1px solid var(--line);
  border-radius: 8px;
}
.analysis-content table {
  min-width: 640px;
  font-size: 13px;
}
.analysis-content th,
.analysis-content td {
  padding: 10px 12px;
}
.side-panel {
  position: sticky;
  top: 16px;
  padding: 14px;
}
.side-panel h2 {
  margin: 3px 0 12px;
  font-size: 16px;
}
.side-panel dl {
  margin: 0;
}
.side-panel dt {
  margin-top: 12px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 800;
  text-transform: uppercase;
}
.side-panel dd {
  margin: 3px 0 0;
  overflow-wrap: anywhere;
}
.side-actions {
  display: grid;
  gap: 8px;
  margin-top: 14px;
}
.side-actions .button,
.side-actions button {
  width: 100%;
}
.empty-panel {
  border: 1px dashed var(--line);
  border-radius: 8px;
  background: var(--panel);
  padding: 28px 18px;
  text-align: center;
}
.empty-panel h2 {
  margin: 0 0 8px;
}
.empty-panel p {
  margin: 0 auto 16px;
  max-width: 560px;
  color: var(--muted);
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
  .analysis-summary,
  .analysis-layout {
    grid-template-columns: 1fr;
  }
  .score-panel {
    grid-template-columns: 1fr;
  }
  .side-panel {
    position: static;
  }
}
"""

ANALYSIS_SECTION_TITLES = (
    "HARDENING SCORE",
    "PROBABLE COMPROMISE / RED-TEAM ARTIFACTS",
    "HARDENING GAPS",
    "SUSPICIOUS PROCESSES / SERVICES / TASKS",
    "DO-NOW CHECKLIST",
)

ANALYSIS_SECTION_LABELS = {
    "HARDENING SCORE": "Hardening Score",
    "PROBABLE COMPROMISE / RED-TEAM ARTIFACTS": "Probable Compromise",
    "HARDENING GAPS": "Hardening Gaps",
    "SUSPICIOUS PROCESSES / SERVICES / TASKS": "Suspicious Tasks",
    "DO-NOW CHECKLIST": "Do-Now Checklist",
}


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


def wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept or "application/xhtml+xml" in accept


def strip_analysis_markup(value: str) -> str:
    text = re.sub(r"^#+\s*", "", value.strip())
    text = re.sub(r"^\d+[\.)]\s*", "", text)
    text = text.replace("**", "").replace("__", "").replace("`", "")
    return text.strip()


def inline_markup(value: str) -> str:
    escaped = html.escape(value.strip())
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return escaped


def match_analysis_section(line: str):
    cleaned = strip_analysis_markup(line)
    upper = cleaned.upper()
    for title in ANALYSIS_SECTION_TITLES:
        if upper.startswith(title):
            return title, cleaned[len(title):].lstrip(" :-")
    return None, ""


def slug_for(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "section"


def split_analysis_sections(text: str) -> list:
    sections = []
    current = None
    intro = []

    for line in text.splitlines():
        title, detail = match_analysis_section(line)
        if title:
            if current:
                sections.append(current)
            current = {"title": title, "lines": []}
            if detail:
                current["lines"].append(detail)
            continue
        if current:
            current["lines"].append(line)
        elif line.strip():
            intro.append(line)

    if current:
        sections.append(current)
    if intro:
        sections.insert(0, {"title": "ANALYSIS SUMMARY", "lines": intro})
    if not sections:
        sections.append({"title": "ANALYSIS OUTPUT", "lines": text.splitlines()})
    return sections


def extract_score(text: str):
    match = re.search(r"(?<!\d)(100|[1-9]?\d)\s*/\s*100", text)
    if not match:
        return None
    return max(0, min(100, int(match.group(1))))


def score_status(score, text: str) -> tuple:
    if text.startswith("[analyzer]"):
        return "danger", "Analyzer error"
    if score is None:
        return "neutral", "Unscored"
    if score >= 80:
        return "ok", "Strong"
    if score >= 60:
        return "warn", "Needs work"
    return "danger", "Critical"


def score_summary(text: str) -> str:
    for line in text.splitlines():
        if re.search(r"(?<!\d)(100|[1-9]?\d)\s*/\s*100", line):
            summary = strip_analysis_markup(line)
            summary = re.sub(r"^HARDENING SCORE\s*[:\-]?\s*", "", summary, flags=re.I)
            return summary or "Score found in analysis output."
    for line in text.splitlines():
        if line.strip():
            return strip_analysis_markup(line)
    return "No analysis text was saved."


def section_item_count(lines: list) -> int:
    count = 0
    for line in lines:
        if re.match(r"^\s*(?:[-*]|\d+[\.)])\s+", line) or "|" in line:
            count += 1
    return count


def table_cells(line: str) -> list:
    stripped = line.strip().strip("|")
    return [cell.strip() for cell in stripped.split("|")]


def is_table_separator(line: str) -> bool:
    cells = table_cells(line)
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell.strip()) for cell in cells)


def is_table_line(line: str) -> bool:
    return len(table_cells(line)) >= 3 and "|" in line


def render_table(lines: list) -> str:
    rows = [table_cells(line) for line in lines if not is_table_separator(line)]
    if not rows:
        return ""
    header, body = rows[0], rows[1:]
    head_html = "".join(f"<th>{inline_markup(cell)}</th>" for cell in header)
    body_rows = []
    for row in body:
        cells = "".join(f"<td>{inline_markup(cell)}</td>" for cell in row)
        body_rows.append(f"<tr>{cells}</tr>")
    body_html = "".join(body_rows) or "<tr><td colspan='3'>No rows</td></tr>"
    return (
        "<div class='table-scroll'><table><thead><tr>"
        f"{head_html}</tr></thead><tbody>{body_html}</tbody></table></div>"
    )


def render_list(tag: str, items: list) -> str:
    rendered = "".join(f"<li>{inline_markup(item)}</li>" for item in items)
    return f"<{tag}>{rendered}</{tag}>"


def render_analysis_blocks(lines: list) -> str:
    html_parts = []
    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue

        if is_table_line(line):
            table_lines = []
            while index < len(lines) and (is_table_line(lines[index]) or is_table_separator(lines[index])):
                table_lines.append(lines[index])
                index += 1
            html_parts.append(render_table(table_lines))
            continue

        bullet_match = re.match(r"^\s*[-*]\s+(.*)$", line)
        if bullet_match:
            items = []
            while index < len(lines):
                match = re.match(r"^\s*[-*]\s+(.*)$", lines[index])
                if not match:
                    break
                items.append(match.group(1))
                index += 1
            html_parts.append(render_list("ul", items))
            continue

        number_match = re.match(r"^\s*\d+[\.)]\s+(.*)$", line)
        if number_match:
            items = []
            while index < len(lines):
                match = re.match(r"^\s*\d+[\.)]\s+(.*)$", lines[index])
                if not match:
                    break
                items.append(match.group(1))
                index += 1
            html_parts.append(render_list("ol", items))
            continue

        html_parts.append(f"<p>{inline_markup(stripped)}</p>")
        index += 1

    return "".join(html_parts) or "<p>No detail was returned for this section.</p>"


def load_report_metadata(host: str) -> dict:
    p = report_path(host)
    if not p.exists():
        return {}
    try:
        payload = json.loads(p.read_text())
    except Exception:
        logger.warning("could not read report metadata host=%s path=%s", host, p)
        return {}
    return {
        "host": payload.get("hostname") or host,
        "collected_as": payload.get("collected_as", "?"),
        "timestamp": payload.get("timestamp", "?"),
        "received": payload.get("_received", "?"),
        "sections": len(payload.get("_decoded", {})),
    }


def render_missing_analysis_page(host: str) -> str:
    host_id = html.escape(safe(host))
    report_exists = report_path(host).exists()
    action = (
        f"<form method='post' action='/analyze/{host_id}'>"
        "<button class='primary' type='submit'>Run Analysis</button></form>"
        if report_exists else
        "<a class='button' href='/'>Back to Dashboard</a>"
    )
    message = (
        "The report exists, but the LLM analysis has not been run for this host."
        if report_exists else
        "No report is stored for this host yet."
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Analysis Pending - {host_id}</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
  <main class="shell">
    <a class="back-link" href="/">Back to dashboard</a>
    <section class="empty-panel">
      <h2>Analysis pending for {host_id}</h2>
      <p>{html.escape(message)}</p>
      <div class="actions" style="justify-content:center">{action}</div>
    </section>
  </main>
</body>
</html>"""


def render_analysis_page(host: str, text: str) -> str:
    metadata = load_report_metadata(host)
    display_host = html.escape(metadata.get("host", host))
    host_id = html.escape(safe(host))
    score = extract_score(text)
    score_class, score_label = score_status(score, text)
    score_value = str(score) if score is not None else "--"
    summary = html.escape(score_summary(text))
    sections = split_analysis_sections(text)
    content_sections = [section for section in sections if section["title"] != "HARDENING SCORE"]
    if not content_sections:
        content_sections = sections

    pills = []
    cards = []
    for section in content_sections:
        title = ANALYSIS_SECTION_LABELS.get(section["title"], section["title"].title())
        section_id = slug_for(title)
        count = section_item_count(section["lines"])
        count_text = f"{count} item{'s' if count != 1 else ''}" if count else "details"
        pills.append(f"<a href='#{section_id}'>{html.escape(title)}</a>")
        cards.append(
            f"<section class='analysis-card' id='{section_id}'>"
            "<header>"
            f"<h2>{html.escape(title)}</h2>"
            f"<span class='count'>{count_text}</span>"
            "</header>"
            f"<div class='analysis-content'>{render_analysis_blocks(section['lines'])}</div>"
            "</section>"
        )

    provider = select_provider()
    side_values = {
        "Collected As": metadata.get("collected_as", "?"),
        "Collected": metadata.get("timestamp", "?"),
        "Received UTC": metadata.get("received", "?"),
        "Sections": str(metadata.get("sections", "?")),
        "Provider": provider,
        "Model": model_for(provider) or "not configured",
    }
    side_rows = "".join(
        f"<dt>{html.escape(label)}</dt><dd>{html.escape(str(value))}</dd>"
        for label, value in side_values.items()
    )
    pill_html = "".join(pills)
    card_html = "".join(cards)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Analysis - {display_host}</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
  <main class="shell">
    <header class="topbar analysis-top">
      <div>
        <a class="back-link" href="/">Back to dashboard</a>
        <p class="eyebrow">LLM Diagnosis</p>
        <h1>Analysis: {display_host}</h1>
      </div>
      <div class="runtime" aria-label="Analysis links">
        <a class="button" href="/report/{host_id}">Report</a>
        <a class="button" href="/analysis/{host_id}?raw=1">Raw Text</a>
      </div>
    </header>

    <section class="analysis-summary" aria-label="Analysis summary">
      <div class="score-panel">
        <div class="score-ring {score_class}">
          <div><strong>{score_value}</strong><span>/100</span></div>
        </div>
        <div class="score-copy">
          <span>Status</span>
          <strong>{html.escape(score_label)}</strong>
          <p>{summary}</p>
        </div>
      </div>
      <div class="summary-panel">
        <span>Sections</span>
        <p>Use this view to scan the saved LLM findings, then open the raw report only when you need source collection detail.</p>
        <nav class="section-pills" aria-label="Analysis sections">{pill_html}</nav>
      </div>
    </section>

    <section class="analysis-layout">
      <div class="analysis-stack">{card_html}</div>
      <aside class="side-panel">
        <span>Host Context</span>
        <h2>{display_host}</h2>
        <dl>{side_rows}</dl>
        <div class="side-actions">
          <form method="post" action="/analyze/{host_id}">
            <button class="primary" type="submit">Run Again</button>
          </form>
          <a class="button" href="/analysis/{host_id}?raw=1">View Raw Analysis</a>
        </div>
      </aside>
    </section>
  </main>
</body>
</html>"""


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
def analyze(host: str, request: Request):
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
    if wants_html(request):
        return RedirectResponse(url=f"/analysis/{safe(host)}", status_code=303)
    return PlainTextResponse(result)


@app.get("/analysis/{host}")
def get_analysis(host: str, request: Request, raw: str = ""):
    p = analysis_path(host)
    if p.exists():
        logger.info("served analysis host=%s path=%s", host, p)
        text = p.read_text()
        if raw or not wants_html(request):
            return PlainTextResponse(text)
        return HTMLResponse(render_analysis_page(host, text))
    logger.info("analysis not found host=%s path=%s", host, p)
    message = f"no analysis yet - POST /analyze/{safe(host)}"
    if raw or not wants_html(request):
        return PlainTextResponse(message)
    return HTMLResponse(render_missing_analysis_page(host))


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
