#!/usr/bin/env python3
"""Diagnostico con LLM de un reporte de hardening recolectado por el agente."""
import os
import textwrap

# IMPORTANTE: pon aqui un modelo al que TU tengas acceso con tu API key.
MODEL = os.environ.get("HARDEN_MODEL", "claude-sonnet-4-5")
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

    try:
        from anthropic import Anthropic
    except ImportError:
        return ("[analyzer] falta la libreria `anthropic`. Corre "
                "`pip install anthropic` y exporta ANTHROPIC_API_KEY.")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        return "[analyzer] ANTHROPIC_API_KEY no esta definida."

    client = Anthropic()
    try:
        msg = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        return (f"[analyzer] fallo la llamada a la API: {e}\n"
                f"Revisa que HARDEN_MODEL ('{MODEL}') sea un modelo al que tengas acceso.")

    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


# ---- swap a otro proveedor (ejemplo OpenAI) ----
# Reemplaza analyze_report(...) por esto si prefieres OpenAI:
#   from openai import OpenAI
#   client = OpenAI()
#   r = client.chat.completions.create(
#       model=os.environ.get("HARDEN_MODEL", "gpt-4o"),
#       messages=[{"role": "system", "content": SYSTEM_PROMPT},
#                 {"role": "user", "content": prompt}])
#   return r.choices[0].message.content
