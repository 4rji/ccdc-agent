#!/usr/bin/env python3
"""LLM diagnosis for a hardening report collected by the agent."""
import os
import textwrap

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-5",
    "openai": "gpt-4o",
}
MAX_REPORT_CHARS = int(os.environ.get("HARDEN_MAX_CHARS", "120000"))

SYSTEM_PROMPT = textwrap.dedent("""\
    You are a senior blue-team operator auditing ONE host during a CCDC-style
    defense competition. Assume a red team may already have access and may have
    planted persistence: extra users, unauthorized SSH keys, cron backdoors,
    systemd timers, SUID root shells, reverse-shell listeners, modified
    rc/profile files, and ld.so.preload hijacks. The blue team is hardening the
    machine under time pressure.

    You are given raw output from an automated collection script. Analyze it and
    produce a concrete, prioritized report. Rules:
    - Quote the EXACT evidence line from the report for each finding.
    - Give remediation commands that are ready to copy and paste.
    - Distinguish "probable red-team artifact / compromise" from "hardening gap".
    - Do not invent findings that the data does not support. If a section is
      empty or says root access is required, say so.
    - Be concise. No preamble or filler.
    """)

USER_TEMPLATE = textwrap.dedent("""\
    HOST: {host}
    COLLECTED_AS: {who}   (if this is not root, coverage is partial)
    TIMESTAMP: {ts}

    Produce these sections in order:

    1. HARDENING SCORE: X/100 - one-line justification.
    2. PROBABLE COMPROMISE / RED-TEAM ARTIFACTS - for each item: evidence line,
       why it is suspicious, remediation command.
    3. HARDENING GAPS - SSH (root login, PasswordAuthentication), firewall
       status, empty-password accounts or duplicate UID 0 accounts, unnecessary
       listening services, world-writable/SUID anomalies, pending updates. Include
       a remediation command for each item.
    4. SUSPICIOUS PROCESSES / SERVICES / TASKS - short table: item | evidence | action.
    5. DO-NOW CHECKLIST - ordered by highest impact first.

    ===== RAW COLLECTION REPORT =====
    {report}
    """)


def build_report_text(decoded: dict) -> str:
    parts = []
    for k, v in decoded.items():
        parts.append(f"===== {k.upper()} =====\n{(v or '').strip()}\n")
    return "\n".join(parts)


def select_provider() -> str:
    configured = os.environ.get("HARDEN_LLM_PROVIDER", "").strip().lower()
    if configured:
        return configured
    if os.environ.get("OPENAI_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY"):
        return "openai"
    return "anthropic"


def model_for(provider: str) -> str:
    return os.environ.get("HARDEN_MODEL", DEFAULT_MODELS.get(provider, ""))


def analyze_with_anthropic(prompt: str) -> str:
    try:
        from anthropic import Anthropic
    except ImportError:
        return ("[analyzer] missing `anthropic` library. Run "
                "`pip install anthropic` and export ANTHROPIC_API_KEY.")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        return ("[analyzer] ANTHROPIC_API_KEY is not set. "
                "For OpenAI, use HARDEN_LLM_PROVIDER=openai and OPENAI_API_KEY.")

    model = model_for("anthropic")
    client = Anthropic()
    try:
        msg = client.messages.create(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        return (f"[analyzer] Anthropic call failed: {e}\n"
                f"Check that HARDEN_MODEL ('{model}') is a model you can access.")

    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


def analyze_with_openai(prompt: str) -> str:
    try:
        from openai import OpenAI
    except ImportError:
        return ("[analyzer] missing `openai` library. Run "
                "`pip install openai` and export OPENAI_API_KEY.")

    if not os.environ.get("OPENAI_API_KEY"):
        return ("[analyzer] OPENAI_API_KEY is not set. "
                "For Anthropic, use HARDEN_LLM_PROVIDER=anthropic and ANTHROPIC_API_KEY.")

    model = model_for("openai")
    client = OpenAI()
    try:
        r = client.chat.completions.create(
            model=model,
            max_tokens=4096,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
    except Exception as e:
        return (f"[analyzer] OpenAI call failed: {e}\n"
                f"Check that HARDEN_MODEL ('{model}') is a model you can access.")

    return r.choices[0].message.content or ""


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

    provider = select_provider()
    if provider == "anthropic":
        return analyze_with_anthropic(prompt)
    if provider == "openai":
        return analyze_with_openai(prompt)
    return "[analyzer] HARDEN_LLM_PROVIDER must be 'anthropic' or 'openai'."
