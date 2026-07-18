# CCDC Hardening Tracker

Agente + servidor Go + diagnostico con LLM para verificar el avance de hardening
de un equipo tipo CCDC. El agente recolecta estado del sistema, lo manda a un
servidor central, y el servidor conserva el reporte mas reciente junto con el
historial de cada envio, muestra un dashboard operativo y puede pedirle a una
LLM un diagnostico priorizado.

```text
[ host 1 ] --\
[ host 2 ] ----> POST /report --> [ server.go ] --analyze--> [ analyzer.py ] --> [ LLM ]
[ host 3 ] --/      ultimo + historial                         + dashboard /
```

## 1. Servidor central

Instala dependencias Python solo si vas a usar `/analyze/<host>`:

```bash
pip install anthropic openai
```

Arranca el servidor Go:

```bash
export HARDEN_TOKEN="ccdcagent2026"      # opcional; ya es el default
export HARDEN_UI_TOKEN="cambia-este-secreto-de-operador"
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
- Correr diagnostico: `POST /analyze/<host>`
- Comprobar el servidor: `GET /healthz`

La autenticacion web esta activa por defecto. En el dialogo del navegador usa
cualquier nombre de usuario y `HARDEN_UI_TOKEN` como contrasena. Si no se
configura, el servidor usa `HARDEN_TOKEN` por compatibilidad y registra una
advertencia. En competencia usa valores separados para que un agente
comprometido no tenga acceso de operador.

### Experiencia web

- El dashboard muestra frescura, cobertura de secciones, identidad de
  recoleccion y estado del analisis por host. Tambien permite buscar hosts y
  filtrar los que requieren atencion, tienen reportes viejos o cobertura
  limitada.
- `GET /report/<host>` ofrece un visor HTML por secciones con busqueda,
  navegacion, plegado/desplegado, ajuste de lineas y copia de cada seccion.
  `GET /report/<host>?raw=1` conserva la salida exacta en texto plano.
- `GET /history/<host>` muestra un timeline. Fusiona el reporte actual con su
  snapshot equivalente para evitar duplicados, resume secciones modificadas y
  lineas agregadas/eliminadas, y pagina los snapshots de 25 en 25 con
  `?page=N`.
- Un analisis puede estar pendiente, vigente, obsoleto (`stale`) o fallido. Si
  llega un reporte mas nuevo, el analisis guardado se marca obsoleto y la
  interfaz permite actualizarlo.
- La descarga PDF usa la paleta del dashboard y presenta score, resumen,
  metadatos, hallazgos, tablas, comandos, continuaciones y pies de pagina como
  un informe operativo estructurado.

### API HTTP

| Metodo | Ruta | Uso |
|--------|------|-----|
| `POST` | `/report` | Recibe un reporte autenticado, actualiza el ultimo y archiva el envio |
| `POST` | `/analyze/<host>` | Ejecuta y guarda el diagnostico LLM |
| `GET` | `/analysis/<host>` | Muestra el analisis guardado y avisa si esta obsoleto |
| `GET` | `/analysis/<host>?raw=1` | Devuelve el analisis como texto plano |
| `GET` | `/analysis/<host>?format=md` | Descarga el analisis como Markdown |
| `GET` | `/analysis/<host>?format=pdf` | Descarga el analisis como PDF |
| `GET` | `/report/<host>` | Muestra el ultimo reporte decodificado como HTML o texto |
| `GET` | `/report/<host>?raw=1` | Devuelve el ultimo reporte como texto plano |
| `GET` | `/history/<host>` | Muestra el timeline deduplicado; cada pagina HTML contiene 25 snapshots archivados |
| `GET` | `/history/<host>?page=N` | Abre otra pagina del timeline HTML |
| `GET` | `/history/<host>/<timestamp>` | Muestra un snapshot como HTML o texto |
| `GET` | `/healthz` | Devuelve `{"status":"ok"}` si el directorio de datos esta disponible; en caso contrario responde HTTP 503 |
| `GET` | `/` | Muestra el estado de la flota |

Las rutas de reporte, historial y analisis negocian el formato. Un navegador
manda `Accept: text/html` y recibe la interfaz HTML. `curl` sin ese encabezado
manda normalmente `Accept: */*`, por lo que conserva la interfaz de texto:
reporte decodificado, lista de timestamps o analisis. Para solicitar HTML de
forma explicita, agrega el encabezado; `?raw=1` siempre fuerza texto plano. Los
agentes usan `HARDEN_TOKEN`; las llamadas API de operador y la autenticacion
Basic del navegador usan `HARDEN_UI_TOKEN` (o el fallback compatible a
`HARDEN_TOKEN`). `/healthz` queda publico.

```bash
curl -H "X-Auth-Token: $HARDEN_UI_TOKEN" http://SERVIDOR:8000/report/web01
curl -H "X-Auth-Token: $HARDEN_UI_TOKEN" -H 'Accept: text/html' http://SERVIDOR:8000/report/web01
curl -H "X-Auth-Token: $HARDEN_UI_TOKEN" -H 'Accept: text/html' 'http://SERVIDOR:8000/history/web01?page=2'
curl -H "X-Auth-Token: $HARDEN_UI_TOKEN" -H 'Accept: text/html' 'http://SERVIDOR:8000/report/web01?raw=1'
```

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
| `HARDEN_UI_TOKEN` | usa `HARDEN_TOKEN` | Secreto separado para operadores del dashboard, reportes, historial y analisis; muy recomendado |
| `HARDEN_ADDR` | `:8000` | Direccion donde escucha el servidor Go |
| `HARDEN_DATA` | `./reports` | Carpeta de reportes y analisis |
| `HARDEN_PROTECT_UI` | `true` | Exige el token de operador en dashboard, reportes, historial y analisis; usa `false` solo en una red aislada y confiable |
| `HARDEN_PYTHON` | `python3` | Python usado para ejecutar `analyzer.py` |
| `HARDEN_STALE_AFTER` | `15m` | Duracion Go tras la cual un reporte se marca viejo, por ejemplo `30m` o `1h` |
| `HARDEN_ANALYZE_TIMEOUT` | `3m` | Tiempo maximo de un proceso de analisis Python |
| `HARDEN_ANALYZE_LIMIT` | `2` | Maximo de analisis simultaneos; el exceso recibe HTTP 429 y `Retry-After: 5` |
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
