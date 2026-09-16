# Redteamcrew (Zotz)

Herramienta de red team orquestada con [LangGraph](https://langchain-ai.github.io/langgraph/)
y llamadas directas al LLM de DeepInfra, sin depender de CrewAI ni litellm.
Esto reduce drásticamente la memoria y el tiempo de arranque del proceso.

## Instalación

Requiere Python >=3.10 <3.14. Se usa [UV](https://docs.astral.sh/uv/):

```bash
uv sync
```

Copia `.env.example` a `.env` y configura:

```
DEEPINFRA_API_KEY=tu_api_key
LLM_MODEL=google/gemma-2-27b-it
```

## Documentación

- **[docs/ARQUITECTURA.md](docs/ARQUITECTURA.md)**: explica en detalle cómo
  funcionan el frontend, el backend y su conexión (REST + SSE).

## Ejecución

Zotz tiene **dos formas de usarse**: el panel web (recomendado) y la CLI.

### 1) Panel web + API (servidor HTTP)

El panel necesita **Redis** (cola API↔worker) y **dos procesos**: la API
(capa HTTP) y el worker (ejecuta el flujo de verdad — LLM, nmap, nuclei).

```bash
redis-server --daemonize yes               # cola de trabajos

uv run redteamcrew-worker &                # ejecuta el flujo
uv run redteamcrew-api                     # http://localhost:8000
uv run redteamcrew-api --host 0.0.0.0 --port 8080
```

Abre `http://localhost:8000` en el navegador, rellena el formulario y pulsa
**Lanzar Workflow**. El panel muestra las fases en vivo (SSE) y, al terminar,
el informe final.

### 2) CLI (interactiva)

La CLI es interactiva: pide los datos del engagement que falten y confirma
antes de lanzar.

```bash
# Interactivo (te pide alcance, nombre, empresa y reglas)
uv run redteamcrew

# Con todos los datos por argumentos
uv run redteamcrew \
  --scope example.com \
  --engagement "engagement-2026" \
  --company "Example Corp" \
  --rules "Solo pruebas no destructivas autorizadas" \
  --out ./outputs

# Automático (no pregunta; usa lo que reciba o deja vacío lo faltante)
uv run redteamcrew --yes --scope example.com --out ./outputs

# Con análisis estático de código local (requiere REDTEAMCREW_SCAN_ROOT)
REDTEAMCREW_SCAN_ROOT=/ruta/de/confianza uv run redteamcrew --scope example.com --code-path mi-proyecto
```

`run_crew` es un alias del mismo entry point (`redteamcrew.main:run`); acepta
los mismos argumentos que `redteamcrew`.

`--scope` solo acepta dominios, IPs o rangos CIDR (nunca una ruta de
filesystem): la validación vive en `redteamcrew/scope.py`.

Al terminar guarda el informe final en `./outputs/<engagement>/informe.md` y lo
imprime en pantalla. `--help` muestra todas las opciones.

El flujo recorre las fases del engagement:

`Reconocimiento → Adaptación de Estrategia → Análisis de Vulnerabilidades → Enumeración de Privilegios → Rutas de Ataque → Explotación (validación por PoC) → Aprobación Humana → Simulación Adversarial → Revisión → Informe`

Ejecución en bucle de la fase de reconocimiento hasta alcanzar suficiencia o
el máximo de iteraciones, usando LangGraph.

## Estructura

```
src/redteamcrew/
├── api/
│   ├── server.py             # API FastAPI (REST + SSE + sirve el panel). Sin estado propio.
│   ├── store.py              # Persistencia SQLite: engagements, hosts, hallazgos
│   └── __main__.py           # Punto de entrada de redteamcrew-api
├── config/
│   ├── agents.yaml          # Roles/objetivos/perfiles de cada fase
│   ├── tasks.yaml           # Descripciones y salidas esperadas
│   └── prompts.py           # Carga e interpolación de prompts desde YAML
├── graph/
│   ├── state.py             # Estado del grafo (AgentState, estado_inicial())
│   └── workflow.py          # Nodos y grafo LangGraph
├── tools/
│   ├── ast_scanner.py       # Análisis estático (AST) de código Python
│   ├── executor.py          # Ejecución real de nmap/nuclei/PoC, con gate de alcance
│   ├── enum_tool.py         # Enumeración de servicios (SSH, HTTP) post-descubrimiento
│   └── osint_tool.py        # Consultas OSINT pasivas a APIs públicas
├── worker.py                 # Worker arq: ejecuta el flujo fuera del proceso API
├── scope.py                  # Validación y enforcement técnico del alcance autorizado
├── llm.py                   # Cliente LLM directo para DeepInfra (urllib)
├── main.py                  # Punto de entrada de la CLI
└── utils/logger.py          # Logging estructurado (structlog)
```

## Herramientas

- `osint_search(query, operation)`: reconocimiento pasivo (DNS, subdominios,
  certificados, IP, CVE, CISA KEV, OTX).
- `scan_ast(path)`: análisis estático de código Python (funciones peligrosas,
  inyección SQL, secretos hardcodeados).
- `run_nmap(target, authorized_scope)` / `run_nuclei(target, authorized_scope)`:
  reconocimiento activo y análisis de vulnerabilidades **reales**, ejecutados
  contra el host. Nunca corren si `scope.resolve_and_check` no autoriza el
  objetivo; se desactivan globalmente con `REDTEAMCREW_ACTIVE_RECON=0`.
- `run_ssh_enum(target, authorized_scope)` / `run_http_enum(target, authorized_scope)`:
  enumeración especializada por servicio, planificada tras el análisis inicial
  (nodo `adaptacion`) y ejecutada en el nodo `analisis`.
- `run_poc(target, plantilla, authorized_scope)`: ejecuta una prueba de
  concepto controlada (nodo `explotacion`) sobre un hallazgo verificado, tras
  aprobación humana cuando corre vía API.

Todas son funciones puras reutilizables por los nodos del grafo.

## Tests

```bash
uv run pytest tests/unit -q                 # unitarios (sin red ni LLM)
uv run pytest tests/integration -q          # integración (requiere API key)
```

## Desarrollo

```bash
uv run ruff check src tests
uv run mypy src/redteamcrew tests
uv run pre-commit run --all-files
```
