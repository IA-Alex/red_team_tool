# Zotz — Cómo funciona el sistema

Este documento explica, de forma clara y sin asumir conocimientos previos, cómo
funciona la herramienta de red team **Zotz**: sus componentes, cómo se conectan
el panel web (frontend) con el motor (backend) y qué ocurre paso a paso cuando
lanzas un engagement.

---

## 1. Visión general

Zotz es una herramienta de **red team** que automatiza un engagement de
seguridad ofensiva: dado un objetivo dentro de un alcance autorizado, recorre
varias **fases** (reconocimiento, análisis, validación, simulación...) y al
final produce un **informe** en Markdown.

Tiene tres piezas de proceso (además del panel):

- **API** (`api/server.py`): capa HTTP delgada. No ejecuta el flujo — solo
  crea el engagement en SQLite y lo **encola**.
- **Worker** (`worker.py`): proceso separado que consume la cola (Redis +
  `arq`) y ejecuta de verdad el grafo LangGraph — LLM, `nmap`, `nuclei`. Así
  una llamada lenta nunca bloquea la API que atiende peticiones HTTP.
- **Un panel web** (frontend) que te permite lanzar un engagement, ver en vivo
  en qué fase va, y descargar el informe final.

El panel habla con la API por HTTP (REST + SSE). La API y el worker se
comunican por Redis: la API encola el trabajo (`arq`) y el worker publica el
progreso a un **stream de Redis** (`engagement:{id}:events`) del que la API
lee y retransmite por SSE.

```
+------------------+ REST/SSE +------------------+  encola   +------------------+
|  Panel web       | -------> |  API (server.py) | --------> |  Redis (arq)     |
|                  | <------- |  (sin estado)     |           |                  |
+------------------+          +--------+---------+           +--------+---------+
                                        ^ lee stream de eventos          | consume job
                                        |                                v
                                        |                       +------------------+
                                        +---------------------- |  Worker          |
                                                                 |  (workflow.py:   |
                                                                 |   LangGraph +    |
                                                                 |   nmap/nuclei +  |
                                                                 |   LLM DeepInfra) |
                                                                 +--------+---------+
                                                                          |
                                                                          v
                                                                 SQLite (api/store.py)
                                                          engagements / hosts / findings
```

---

## 2. Componentes

| Componente | Archivo | Qué hace |
|---|---|---|
| **Panel web** | `frontend_zotz_web_panel.html` | Interfaz de usuario (HTML+CSS+JS sin frameworks). |
| **Servidor API** | `src/redteamcrew/api/server.py` | Capa HTTP: crea/encola engagements, retransmite SSE, sirve informes y el panel. No ejecuta el flujo. |
| **Worker** | `src/redteamcrew/worker.py` | Proceso `arq` que ejecuta el flujo de verdad y publica progreso a Redis. |
| **Grafo del flujo** | `src/redteamcrew/graph/workflow.py` | Define las fases del red team como un grafo de LangGraph. |
| **Estado** | `src/redteamcrew/graph/state.py` | El "cuaderno" donde cada fase escribe sus resultados (`estado_inicial()` es el único punto de verdad de su forma). |
| **Alcance autorizado** | `src/redteamcrew/scope.py` | Valida el formato de `authorized_scope` y, vía `resolve_and_check`, es el chokepoint técnico que autoriza (o no) cada ejecución activa contra un objetivo concreto. |
| **Cliente LLM** | `src/redteamcrew/llm.py` | Habla con DeepInfra (urllib, sin librerías pesadas). |
| **Herramientas pasivas** | `src/redteamcrew/tools/osint_tool.py`, `ast_scanner.py` | Reconocimiento OSINT y análisis estático de código. |
| **Herramientas activas** | `src/redteamcrew/tools/executor.py` | Ejecuta `nmap`/`nuclei` de verdad contra el alcance autorizado (siempre tras pasar `scope.resolve_and_check`). |
| **Persistencia** | `src/redteamcrew/api/store.py` | SQLite: engagements, hosts descubiertos y hallazgos (con `origen`: `herramienta` o `modelo`). |
| **Prompts** | `src/redteamcrew/config/` | Plantillas (YAML) de roles y tareas de cada fase. |
| **Logging** | `src/redteamcrew/utils/logger.py` | Registro estructurado (structlog) en JSON. |

---

## 3. El flujo de red team (las fases)

El motor ejecuta un **grafo** donde cada "nodo" es una fase. Los nodos reales,
en orden de ejecución (`src/redteamcrew/graph/workflow.py:build_workflow`),
son:

```
Reconocimiento → Adaptación de Estrategia → Análisis de Vulnerabilidades
→ Enumeración de Privilegios → Rutas de Ataque (pathfinding)
→ Explotación (validación controlada mediante PoC) → Aprobación Humana
→ Simulación Adversarial → Revisión → Informe
```

Cada nodo:

1. Lee lo que las fases anteriores escribieron en el **estado** (`AgentState`).
2. Arma un prompt (rol + tarea) desde los YAML de configuración, o ejecuta
   directamente una herramienta (los nodos de reconocimiento, enumeración,
   pathfinding y explotación combinan llamadas a herramientas con LLM).
3. Escribe el resultado de vuelta en el estado.

Un detalle del grafo: la fase de **Reconocimiento** se repite en bucle hasta
reunir suficientes hallazgos (`suficiencia`) o llegar al máximo de iteraciones.
Ese nodo de control (`suficiencia`) es **interno**: no se muestra en el panel.

El panel web muestra los 10 nodos visibles (todos excepto `suficiencia`) como
pasos del timeline; el nombre de nodo que emite el backend por SSE coincide
exactamente con el `data-phase` de cada paso.

> Dos fases pausan el grafo con human-in-the-loop de LangGraph (`interrupt` +
> checkpointer en memoria) cuando se ejecutan vía la API: **Explotación**
> (aprobación por cada hallazgo antes de correr su PoC) y **Aprobación
> Humana** (aprobación final del engagement, vía `POST
> /api/engagements/{id}/approve`). La CLI, en cambio, compila el grafo sin
> checkpointer y usa las variantes automáticas de ambos nodos
> (`explotacion_auto_nodo`, `aprobacion_auto_nodo`), porque el operador ya
> confirmó el engagement de forma interactiva antes de lanzarlo y no hay
> mecanismo de reanudación en la CLI.

---

## 4. La API (endpoints)

El servidor FastAPI expone lo siguiente:

| Método | Ruta | Función |
|---|---|---|
| `GET` | `/` | Sirve el panel web (frontend). |
| `POST` | `/api/engagements` | Crea un engagement y lanza el flujo. Devuelve `{ "id": "..." }`. |
| `GET` | `/api/engagements/{id}/events` | Canal **SSE** con las fases en tiempo real. |
| `POST` | `/api/engagements/{id}/approve` | Resuelve una aprobación humana pendiente (PoC de explotación o aprobación final) (`{"aprobado": bool, "comentario": str}`). |
| `GET` | `/api/engagements/{id}/graph` | Grafo de activos descubiertos (nodos/enlaces, formato `networkx` node-link) para renderizar con Cytoscape en el panel. |
| `GET` | `/api/engagements/{id}/informe.md` | Informe final en Markdown (cuando termina). |
| `GET` | `/api/engagements/{id}/informe.html` | Informe final renderizado a HTML (cuando termina). |

Si se configura `REDTEAMCREW_API_KEY`, los endpoints `POST` exigen la cabecera
`X-API-Key` con esa clave (401 si falta o no coincide). `POST
/api/engagements` además está limitado a 5 peticiones cada 5 minutos por IP
(429 al superarlo).

Ejemplo de creación:

```bash
curl -X POST http://localhost:8000/api/engagements \
  -H "Content-Type: application/json" \
  -d '{
    "engagement_name": "Operación Sombra",
    "company_name": "Acme Corp",
    "authorized_scope": "example.com",
    "rules_of_engagement": "Solo pruebas pasivas"
  }'
```

Respuesta:

```json
{ "id": "e698c80b220a477eb83fcc4c1afcafbc" }
```

---

## 5. Cómo se comunican frontend y backend

### 5.1 Lanzar un engagement (REST)

Cuando pulsas **"Lanzar Workflow"** en el panel:

1. El JavaScript del frontend valida el formulario (el **alcance autorizado**
   es obligatorio) y hace un `POST` a `/api/engagements` con los datos.
2. El backend crea el engagement, le asigna un `id`, y lanza el flujo en un
   **hilo de fondo** (`asyncio.create_task`). Responde al instante con el `id`
   —no espera a que el flujo termine.
3. Con ese `id`, el frontend abre la conexión SSE.

### 5.2 Ver el progreso (SSE)

**SSE** (Server-Sent Events) es un canal unidireccional donde el servidor
empuja eventos al navegador sin que este tenga que preguntar.

1. El frontend abre `new EventSource('/api/engagements/{id}/events')`.
2. A medida que cada nodo del grafo termina, el backend lo encola y lo envía
   como un evento `fase` con el nombre del nodo.
3. El panel actualiza el **timeline** marcando la fase activa y las anteriores
   como completadas.

Eventos que envía el servidor:

| Evento | Significado |
|---|---|
| `conectado` | El canal SSE se estableció. |
| `fase` | Un nodo terminó. `data` contiene el nombre de la fase. |
| `aprobacion_requerida` | El grafo se pausó esperando una decisión humana (PoC de explotación o aprobación final). El panel muestra un banner con el detalle y botones Aprobar/Rechazar que llaman a `POST .../approve`. |
| `completado` | El flujo terminó con éxito. |
| `error` | El flujo falló. `data` contiene el mensaje. |

Cada evento tiene este formato:

```
event: fase
data: {"data": "reconocimiento"}

```

### 5.3 Ver el informe

Cuando llega el evento `completado`, el panel:

1. Hace `GET /informe.html` y muestra el informe dentro de un **`<iframe>`
   aislado** (sandbox) para que ningún markup del informe pueda ejecutar
   scripts (protección contra XSS).
2. Activa el botón "Descargar Markdown", que apunta a `GET /informe.md`.

> Los endpoints de informe devuelven **HTTP 409** mientras el flujo aún corre,
> porque el informe todavía no existe.

### 5.4 Robustez de la conexión

El frontend está preparado para fallos:

- **Reconexión**: si la conexión SSE se cae (error de red), reintenta hasta 5
  veces con espera creciente.
- **Errores de servidor**: si el backend envía un evento `error`, se muestra y
  se detiene.
- La distinción se hace mirando si el evento trae `data` (error de servidor) o
  no (error de transporte).

---

## 6. Ciclo completo de un engagement (paso a paso)

1. Abres `http://localhost:8000` → se carga el panel.
2. Rellenas el formulario y pulsas **Lanzar Workflow**.
3. El frontend hace `POST /api/engagements`.
4. El backend crea el engagement y lanza el flujo en segundo plano.
5. El frontend abre el canal SSE con el `id`.
6. El backend recorre las fases: cada una escribe su resultado en el estado y
   emite un evento `fase`.
7. El panel va marcando la fase activa en el timeline.
7b. Si el grafo se pausa (PoC de explotación o aprobación final), el backend
    emite `aprobacion_requerida`; el panel muestra el banner de decisión y
    espera a que el operador apruebe o rechace (`POST .../approve`) para que
    el worker reanude el mismo flujo desde el punto de pausa.
8. Al terminar, el backend emite `completado` y guarda el informe (MD + HTML).
9. El panel muestra el informe en el iframe y activa la descarga del `.md`.

---

## 7. Cómo levantar y usar

### Requisitos

- Python ≥ 3.10 y < 3.14, con [UV](https://docs.astral.sh/uv/).
- Una clave de API de DeepInfra en `.env` (ver `.env.example`).
- **Redis** corriendo (la cola API↔worker). En Kali/Debian: `sudo apt install
  redis-server && redis-server --daemonize yes`.
- Para recon/análisis activo real: `nmap` y `nuclei` instalados en el host
  (ya vienen en Kali). Sin ellos, o con `REDTEAMCREW_ACTIVE_RECON=0`, el
  flujo sigue funcionando solo con OSINT pasivo.

### Instalar y arrancar

El panel web necesita **dos procesos** además de Redis: la API y el worker.

```bash
uv sync                                   # instala dependencias
cp .env.example .env                      # y rellena DEEPINFRA_API_KEY

redis-server --daemonize yes              # cola API <-> worker

uv run redteamcrew-worker &               # ejecuta el flujo (LLM, nmap, nuclei)
uv run redteamcrew-api                    # servidor en http://localhost:8000
# o con parámetros:
uv run redteamcrew-api --host 0.0.0.0 --port 8080
```

Abre `http://localhost:8000` en el navegador.

### Sólo el motor (sin panel)

También existe la CLI original, que pide los datos interactivamente:

```bash
uv run redteamcrew --scope example.com --engagement "Op" --company "Acme" --out ./outputs
```

---

## 8. Seguridad y control de acceso

- **Alcance autorizado validado**: `authorized_scope` solo acepta dominios,
  IPs o rangos CIDR (`redteamcrew/scope.py`). Nunca se interpreta como ruta de
  archivo del servidor.
- **Análisis de código local aislado**: el escaneo AST de código local
  (`analisis_nodo`) está deshabilitado por defecto y solo se activa si el
  operador configura `REDTEAMCREW_SCAN_ROOT` (una raíz de confianza) y la ruta
  pedida (`local_code_path`, solo disponible por CLI con `--code-path`) cae
  dentro de esa raíz. No se dispara automáticamente desde el panel web.
- **Autenticación por API key**: si se define `REDTEAMCREW_API_KEY`, los
  endpoints `POST` requieren la cabecera `X-API-Key`.
- **Rate limiting**: `POST /api/engagements` está limitado por IP (5 cada 5
  minutos) para evitar abuso de créditos del LLM.
- **Aprobación humana real**: vía API, el flujo se pausa de verdad en la fase
  de aprobación (`interrupt` + checkpointer) hasta `POST .../approve`.
- **Recon/análisis activo real, con gate de alcance**: `analisis_nodo` y
  `reconocimiento_nodo` ejecutan `nmap`/`nuclei` de verdad
  (`tools/executor.py`) contra el objetivo, nunca sin pasar antes por
  `scope.resolve_and_check` — un objetivo fuera de `authorized_scope` no
  llega a ejecutarse, aunque el LLM lo hubiera sugerido.
- **Hallazgos con procedencia distinguible**: cada hallazgo se guarda con
  `origen: 'herramienta'` (verificado por ejecución real) o `'modelo'`
  (síntesis narrativa del LLM) — nunca mezclados bajo la misma etiqueta en
  el informe final.

## 9. Limitaciones actuales

- **SSE en vivo es por engagement, no por servidor**: los eventos se leen
  desde un stream de Redis (no memoria del proceso), así que múltiples
  instancias de la API pueden servir el mismo canal SSE. El checkpointer de
  aprobación humana (LangGraph `MemorySaver`), en cambio, sigue viviendo en
  memoria del **worker** — solo puede correr un worker a la vez mientras
  haya engagements pausados esperando aprobación.
- **Cada llamada al LLM/herramienta puede tardar**: el flujo completo puede
  tomar varios minutos (varias llamadas a DeepInfra + nmap + nuclei),
  especialmente con recon activo habilitado.
- **Recon activo es determinista, no agéntico**: en esta fase, la secuencia
  nmap → nuclei está fijada en el código; el LLM interpreta y prioriza los
  resultados, pero no decide todavía qué herramienta correr a continuación.
- **Solo el objetivo primario del alcance se escanea activamente**: si
  `authorized_scope` trae varios objetivos separados por coma, `nmap`/
  `nuclei` solo corren contra el primero.
- **Explotación activa ya ejecuta PoCs reales**: el nodo `explotacion`
  (`explotacion_manual_nodo` vía API, `explotacion_auto_nodo` vía CLI) corre
  `run_poc` por cada hallazgo verificado. Vía API, cada PoC individual pasa
  por aprobación humana (`interrupt`); vía CLI se ejecutan todos sin pausa.
  Sigue pendiente: sandboxing dedicado de la ejecución del PoC.
- **Presentación del informe**: el LLM a veces envuelve el informe en un bloque
  ```` ```markdown ````, por lo que en HTML puede mostrarse como código en vez
  de títulos formateados.
