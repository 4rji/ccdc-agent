# Diseño: resumen de reportes guardados + vista cruda navegable

Fecha: 2026-07-17
Estado: aprobado

## Problema

El manejo de historial y reportes es inconsistente:

- `/history/<host>` es una lista de botones con timestamps crudos
  (`20260717T205948.482136Z`), sin información sobre qué contiene cada reporte.
- `/report/<host>` y `/history/<host>/<stamp>` devuelven texto plano directo:
  sin navegación, sin estilo, el usuario queda "atrapado" en la página.
- El historial vacío renderiza la página de "Analysis pending", un mensaje
  equivocado para ese contexto.
- `server.py` (legacy FastAPI) no tiene soporte de historial en absoluto: ni
  archiva copias al recibir reportes ni expone rutas `/history/`.

## Objetivo

Una página de resumen de los reportes guardados por host (fecha legible +
líneas totales por reporte), desde la cual se abre la vista cruda de cada
reporte, ahora envuelta en HTML navegable. Paridad completa entre `server.go`
y `server.py`.

## Diseño

### 1. Página de resumen `/history/<host>` (GET, HTML)

Tabla con el estilo existente del dashboard (`dashboardCSS`), columnas:

| Columna  | Contenido |
|----------|-----------|
| Fecha    | Legible, ej. `2026-07-17 20:59:48 UTC`. Snapshots: derivada del nombre del archivo (`20060102T150405.000000Z`); fila "Actual": del campo `_received` del payload |
| Líneas   | Total de líneas del reporte decodificado (salida de `formatDecodedReport`) |
| Acciones | Botón "Ver reporte" |

- Primera fila: el reporte actual (`reports/<host>.json`) con badge "Actual",
  enlaza a `/report/<host>`.
- Debajo: snapshots de `reports/history/<host>/*.json`, el más reciente
  primero, cada uno enlaza a `/history/<host>/<stamp>`.
- Las líneas se cuentan leyendo cada JSON al renderizar. Sin índice ni caché:
  a escala de competencia (decenas de archivos por host) es instantáneo.
- JSON corrupto o ilegible: la fila se muestra con la fecha (del nombre de
  archivo) y "ilegible" en la columna de líneas, sin romper la página.
- Cliente no-HTML (curl): sigue devolviendo la lista de timestamps en texto
  plano, sin cambios en la API.

### 2. Vista cruda `/report/<host>` y `/history/<host>/<stamp>` (GET)

- Con `Accept: text/html`: página HTML con `dashboardCSS`, link de regreso al
  historial y al dashboard, título con host y fecha, contador de líneas, y el
  reporte decodificado en un bloque `<pre>` monoespaciado con scroll
  horizontal. Botones: "Texto plano" (`?raw=1`), "History", "Analysis".
- Con `?raw=1` o cliente no-HTML: texto plano exacto como hoy. La API para
  curl/scripts no cambia.
- Se agrega a `dashboardCSS` el estilo para `<pre>` (monospace, borde de
  panel, `overflow-x: auto`), que hoy no existe.

### 3. Historial vacío

Página propia y simple: "Sin historial para <host>" con link de regreso al
dashboard (y botón al reporte actual si existe). Reemplaza el uso incorrecto
de `renderMissingAnalysisPage`. Respuesta de texto plano sin cambios.

### 4. Paridad en `server.py`

Portar de Go a FastAPI lo que hoy solo existe en `server.go`, más lo nuevo:

- Al recibir un reporte (`POST /report`): guardar copia en
  `reports/history/<host>/<stamp>.json` (mismo formato de timestamp que Go).
- Rutas `GET /history/{host}` (página de resumen) y
  `GET /history/{host}/{stamp}` (vista cruda), con el mismo HTML.
- `GET /report/{host}`: mismo comportamiento de envoltura HTML / `?raw=1`.
- Botón "History" en las filas del dashboard.

### Manejo de errores

- Host sin reporte: 404, como hoy.
- Snapshot inexistente: 404, como hoy.
- JSON corrupto en historial: fila "ilegible" en el resumen; en la vista
  cruda, mensaje de error legible en vez de 500.

### Pruebas

- `server_test.go`: página de resumen lista entradas con conteo de líneas
  (incluye fila "Actual"); vista cruda devuelve HTML con `Accept: text/html`
  y texto plano con `?raw=1`; historial vacío muestra su propia página (no la
  de "Analysis pending").
- `server.py`: verificación manual con `curl` (no existe suite de tests
  Python hoy).

## Fuera de alcance

- Índices o caché de metadata precomputada.
- Pestañas client-side / JavaScript.
- Diff entre snapshots, líneas por sección, tamaño de archivo (descartados en
  la conversación de diseño: se pidió mantenerlo simple).
