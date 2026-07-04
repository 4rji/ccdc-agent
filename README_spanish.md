# CCDC Hardening Tracker

Agente + servidor Go + diagnostico con LLM para verificar el avance de hardening
de un equipo tipo CCDC. El agente recolecta estado del sistema, lo manda a un
servidor central, y el servidor guarda el reporte, muestra dashboard y puede
pedirle a una LLM un diagnostico priorizado.

```text
[ host 1 ] --\
[ host 2 ] ----> POST /report --> [ server.go ] --analyze--> [ analyzer.py ] --> [ LLM ]
[ host 3 ] --/      guarda por host                            + dashboard /
```

## 1. Servidor central

Instala dependencias Python solo si vas a usar `/analyze/<host>`:

```bash
pip install anthropic openai
```

Arranca el servidor Go:

```bash
export HARDEN_TOKEN="ccdcagent2026"      # opcional; ya es el default
export ANTHROPIC_API_KEY="sk-ant-..."
go run .
```

Para escuchar en todas las interfaces:

```bash
HARDEN_ADDR="0.0.0.0:8000" go run .
```

Para usar OpenAI en vez de Anthropic:

```bash
export HARDEN_LLM_PROVIDER="openai"
export OPENAI_API_KEY="sk-..."
export HARDEN_MODEL="gpt-4o"             # opcional; default gpt-4o
go run .
```

- Dashboard: `http://SERVIDOR:8000/`
- Ver reporte crudo: `GET /report/<host>`
- Correr diagnostico: `POST /analyze/<host>`
- Ver ultimo analisis: `GET /analysis/<host>`
- Ver analisis como texto: `GET /analysis/<host>?raw=1`

## 2. Agente en cada maquina

Prueba local primero, sin mandar nada:

```bash
sudo ./hardening_agent.sh text
sudo ./hardening_agent.sh local
```

Enviar al servidor:

```bash
sudo HARDEN_SERVER="http://SERVIDOR:8000/report" \
     HARDEN_TOKEN="ccdcagent2026" \
     ./hardening_agent.sh send
```

Correr como root da mejor cobertura: `/etc/shadow`, crontabs de usuarios y
`authorized_keys`. No exporta hashes de contrasena, solo su estado:
`set` / `locked` / `EMPTY!`.

## 3. Variables

| Variable | Default | Uso |
|----------|---------|-----|
| `HARDEN_SERVER` | `http://127.0.0.1:8000/report` | URL donde el agente manda reportes |
| `HARDEN_TOKEN` | `ccdcagent2026` | Secreto compartido entre agente y servidor |
| `HARDEN_ADDR` | `:8000` | Direccion donde escucha el servidor Go |
| `HARDEN_DATA` | `./reports` | Carpeta de reportes y analisis |
| `HARDEN_PYTHON` | `python3` | Python usado para ejecutar `analyzer.py` |
| `HARDEN_LLM_PROVIDER` | `anthropic` | `anthropic` u `openai` |
| `HARDEN_MODEL` | depende del proveedor | Modelo LLM |
| `HARDEN_MAX_CHARS` | `120000` | Limite de caracteres enviados a la LLM |

## 4. Automatizar el agente

### Opcion A: cron cada 10 minutos

```bash
sudo cp hardening_agent.sh /usr/local/bin/hardening_agent.sh
sudo chmod +x /usr/local/bin/hardening_agent.sh
echo '*/10 * * * * root HARDEN_SERVER=http://SERVIDOR:8000/report HARDEN_TOKEN=ccdcagent2026 /usr/local/bin/hardening_agent.sh send >/var/log/harden-agent.log 2>&1' | sudo tee /etc/cron.d/hardening-agent
```

### Opcion B: systemd timer

```ini
# /etc/systemd/system/hardening-agent.service
[Unit]
Description=CCDC hardening collector

[Service]
Type=oneshot
Environment=HARDEN_SERVER=http://SERVIDOR:8000/report
Environment=HARDEN_TOKEN=ccdcagent2026
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

## 5. Validacion

```bash
GOCACHE=/private/tmp/ccdc-go-cache go test ./...
bash -n hardening_agent.sh
python3 -m py_compile analyzer.py server.py
```

## Notas de seguridad

- Usa TLS con nginx/caddy o manten el servidor solo en la red interna.
- `HARDEN_TOKEN` evita spam basico, no es autenticacion fuerte.
- No subas API keys, tokens ni reportes generados.
- El servidor centraliza datos sensibles de todas las maquinas; aislalo.
