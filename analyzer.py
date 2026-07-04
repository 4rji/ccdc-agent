#!/usr/bin/env python3
"""Diagnostico con LLM de un reporte de hardening recolectado por el agente."""
import os
import textwrap

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-5",
    "openai": "gpt-4o",
}
MAX_REPORT_CHARS = int(os.environ.get("HARDEN_MAX_CHARS", "120000"))

SYSTEM_PROMPT = textwrap.dedent("""\
    Eres un operador senior de blue-team auditando UN host durante una
    competencia de defensa tipo CCDC. Asume que un red team ya tiene accesos y
    planta persistencia: usuarios extra, llaves SSH no autorizadas, backdoors en
    cron y en systemd-timers, shells SUID root, listeners de reverse-shell,
    archivos rc/profile modificados y secuestros de ld.so.preload. El blue team
    intenta endurecer la maquina contra reloj.

    Se te entrega la salida cruda de un script de recoleccion automatico.
    Analizala y produce un reporte concreto y priorizado. Reglas:
    - Cita la LINEA EXACTA de evidencia del reporte cuando marques algo.
    - Da comandos de remediacion listos para copiar/pegar.
    - Distingue "artefacto probable de red-team / compromiso" de "brecha de hardening".
    - No inventes hallazgos que los datos no respalden. Si una seccion esta vacia
      o dice que necesita root, dilo.
    - Se conciso. Sin preambulo ni relleno.
    """)

USER_TEMPLATE = textwrap.dedent("""\
    HOST: {host}
    RECOLECTADO_COMO: {who}   (si no es root, la cobertura es parcial)
    TIMESTAMP: {ts}

    Produce estas secciones en orden:

    1. SCORE DE HARDENING: X/100 — una linea de justificacion.
    2. COMPROMISO PROBABLE / ARTEFACTOS DE RED-TEAM — por cada uno: linea de
       evidencia, por que es sospechoso, comando de arreglo.
    3. BRECHAS DE HARDENING (lo que aun les falta) — SSH (login de root,
       PasswordAuthentication), estado del firewall, cuentas con password vacio o
       UID 0 duplicado, servicios en escucha innecesarios, anomalias
       world-writable/SUID, updates pendientes. Cada una con comando de arreglo.
    4. PROCESOS / SERVICIOS / TAREAS SOSPECHOSAS — tabla corta: item | evidencia | accion.
    5. CHECKLIST HAZLO-YA — ordenado, lo de mayor impacto primero.

    ===== REPORTE CRUDO DE RECOLECCION =====
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
        return ("[analyzer] falta la libreria `anthropic`. Corre "
                "`pip install anthropic` y exporta ANTHROPIC_API_KEY.")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        return ("[analyzer] ANTHROPIC_API_KEY no esta definida. "
                "Para OpenAI usa HARDEN_LLM_PROVIDER=openai y OPENAI_API_KEY.")

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
        return (f"[analyzer] fallo la llamada a Anthropic: {e}\n"
                f"Revisa que HARDEN_MODEL ('{model}') sea un modelo al que tengas acceso.")

    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


def analyze_with_openai(prompt: str) -> str:
    try:
        from openai import OpenAI
    except ImportError:
        return ("[analyzer] falta la libreria `openai`. Corre "
                "`pip install openai` y exporta OPENAI_API_KEY.")

    if not os.environ.get("OPENAI_API_KEY"):
        return ("[analyzer] OPENAI_API_KEY no esta definida. "
                "Para Anthropic usa HARDEN_LLM_PROVIDER=anthropic y ANTHROPIC_API_KEY.")

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
        return (f"[analyzer] fallo la llamada a OpenAI: {e}\n"
                f"Revisa que HARDEN_MODEL ('{model}') sea un modelo al que tengas acceso.")

    return r.choices[0].message.content or ""


def analyze_report(payload: dict) -> str:
    decoded = payload.get("_decoded", {})
    report = build_report_text(decoded)
    if len(report) > MAX_REPORT_CHARS:
        report = report[:MAX_REPORT_CHARS] + "\n...[truncado]..."

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
    return "[analyzer] HARDEN_LLM_PROVIDER debe ser 'anthropic' u 'openai'."
