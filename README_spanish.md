# CCDC Hardening Tracker

Agente + servidor + diagnostico con LLM para verificar el avance de hardening de
un equipo tipo CCDC. El agente recolecta el estado del sistema (servicios,
procesos, tareas programadas, permisos, usuarios, red, firewall, persistencia),
lo manda a un servidor central, y el servidor usa una LLM para decir **que les
falto**, **que corre**, y **que se ve comprometido**.

```
[ host 1 ] --\
[ host 2 ] ---->  POST /report  -->  [ server.py ]  --analyze-->  [ LLM ]  -->  reporte
[ host 3 ] --/                         (guarda por host)                      + dashboard /
```

## 1. Servidor central

```bash
pip install fastapi uvicorn anthropic
export HARDEN_TOKEN="un-secreto-largo"        # mismo token que los agentes
export ANTHROPIC_API_KEY="sk-ant-..."
export HARDEN_MODEL="claude-sonnet-4-5"       # pon un modelo al que tengas acceso
uvicorn server:app --host 0.0.0.0 --port 8000
```

- Dashboard: `http://SERVIDOR:8000/`
- Ver reporte crudo: `GET /report/<host>`
- Correr diagnostico: `POST /analyze/<host>`  → devuelve el analisis en texto
- Ver ultimo analisis: `GET /analysis/<host>`

## 2. Agente en cada maquina del equipo

Prueba local primero (no manda nada):

```bash
sudo ./hardening_agent.sh text     # volcado legible
sudo ./hardening_agent.sh local    # JSON crudo
```

Enviar al servidor:

```bash
sudo HARDEN_SERVER="http://SERVIDOR:8000/report" \
     HARDEN_TOKEN="un-secreto-largo" \
     ./hardening_agent.sh send
```

Correr como **root** para ver estado de `/etc/shadow`, todos los crontabs y
todas las `authorized_keys`. (No exporta hashes de contrasena, solo su estado:
`set` / `locked` / `EMPTY!`.)

## 3. "Correrlo despues de la sesion" — automatizar

### Opcion A: cron (cada 10 min)
```bash
sudo cp hardening_agent.sh /usr/local/bin/hardening_agent.sh
sudo chmod +x /usr/local/bin/hardening_agent.sh
echo '*/10 * * * * root HARDEN_SERVER=http://SERVIDOR:8000/report HARDEN_TOKEN=un-secreto-largo /usr/local/bin/hardening_agent.sh send >/var/log/harden-agent.log 2>&1' | sudo tee /etc/cron.d/hardening-agent
```

### Opcion B: systemd timer (agente "instalado")
```ini
# /etc/systemd/system/hardening-agent.service
[Unit]
Description=CCDC hardening collector
[Service]
Type=oneshot
Environment=HARDEN_SERVER=http://SERVIDOR:8000/report
Environment=HARDEN_TOKEN=un-secreto-largo
ExecStart=/usr/local/bin/hardening_agent.sh send
```
```ini
# /etc/systemd/system/hardening-agent.timer
[Unit]
Description=Run CCDC hardening collector periodically
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

## Flujo de uso tipico

1. El equipo termina una tanda de hardening.
2. En cada host: `hardening_agent.sh send` (o esperas al timer).
3. En el servidor, por cada host: `curl -X POST http://SERVIDOR:8000/analyze/HOST`
4. Lees el reporte del LLM: score, artefactos de red-team, brechas pendientes,
   procesos/servicios/tareas sospechosas y checklist priorizado.

## Notas de seguridad (importantes en un entorno con red team activo)

- **Usa TLS** (pon el servidor detras de nginx/caddy con HTTPS) o mantenlo solo
  en la red interna de scoring. El reporte lleva datos sensibles (llaves SSH,
  config, listeners).
- El `HARDEN_TOKEN` solo evita spam basico; no lo trates como auth fuerte.
- El servidor centraliza info de todas las cajas: si lo comprometen, es una mina
  de oro. Aislalo y no dejes ahi tus API keys en claro mas de lo necesario.
- El agente **solo lee** estado; no cambia nada. Los arreglos los aplicas tu con
  los comandos que sugiere el diagnostico.

## Extensiones faciles

- Diff contra un **baseline** (guarda el primer reporte "limpio" y compara los
  siguientes para resaltar cambios = actividad de red team).
- Endpoint `/scoreboard` que ordene los hosts por score del LLM.
- Integrar `lynis audit system --quick` y `chkrootkit` y meter su salida como
  secciones extra del reporte.
- Alertas: si aparece un UID 0 nuevo, password EMPTY!, o un listener nuevo,
  mandar aviso a Slack/Discord webhook.
