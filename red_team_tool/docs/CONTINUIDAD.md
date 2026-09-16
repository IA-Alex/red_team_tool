# Continuidad — Zotz (redteamcrew)

> Documento de traspaso. Objetivo: que otro modelo/operador retome el trabajo
> sin releer todo el historial de conversación. Fecha de este corte:
> 2026-09-15. Rama: `main`, sin commitear todavía (ver `git status` — todo lo
> de esta sesión está en el working tree, nada pusheado).

## 1. Qué es Zotz, en una frase

Herramienta de red team: un grafo LangGraph de 7 fases (Reconocimiento →
Análisis → Validación → Aprobación Humana → Simulación → Revisión → Informe)
orquestado por LLM (DeepInfra), expuesto por una API FastAPI + panel web, con
CLI alternativa. Nombre técnico del paquete: `redteamcrew`. Marca: `Zotz`.

## 2. Estado actual en una frase

**El pipeline ejecuta herramientas reales (nmap/nuclei) con alcance forzado
técnicamente y corre de punta a punta de verdad (verificado en vivo), pero el
informe final todavía puede contener vulnerabilidades inventadas por el LLM
sin respaldo en los hallazgos verificados — ese es el hueco abierto más
importante ahora mismo (sección 6).**

## 3. Qué se hizo, en orden cronológico

### 3.1 Auditoría de arquitectura + seguridad (primera pasada)
Se auditó el repo como estaba (recién migrado de CrewAI a LangGraph, con una
API FastAPI/SSE sin comitear). Hallazgos corregidos:
- **Crítico — LFI**: `authorized_scope` podía interpretarse como ruta de
  filesystem del servidor (`analisis_nodo` hacía `os.path.exists(objetivo)`
  y escaneaba lo que encontrara). → Ahora el escaneo de código local requiere
  un campo explícito `local_code_path` + `REDTEAMCREW_SCAN_ROOT` configurado;
  nunca se deriva del alcance. Ver `graph/workflow.py::_resolver_ruta_codigo_local`.
- **Alto — API sin auth/rate limit** → `REDTEAMCREW_API_KEY` (header
  `X-API-Key`) + rate limit 5/5min por IP en `POST /api/engagements`.
- **Alto — estado 100% en memoria** → persistencia SQLite (`api/store.py`).
- **Medio — "Aprobación Humana" era un no-op** → ahora usa `interrupt()` +
  `MemorySaver` de LangGraph: el grafo se pausa de verdad
  (`aprobacion_manual_nodo` en `graph/workflow.py`), la API expone
  `POST /api/engagements/{id}/approve` para resolverlo.
- **Medio — scope solo validado por formato** → `scope.py::validate_scope`
  (dominio/IP/CIDR, rechaza rutas de filesystem).

### 3.2 Auditoría de identidad (Zotz / ocelotl_agent)
`docs/IDENTITY.md` afirmaba cosas falsas sobre el código (un `crew.py` que ya
no existe, claves `ocelotl_agent_*` que nunca se usaban). Se alineó el código
con la identidad documentada: `config/agents.yaml` y las constantes `AGENT_*`
en `graph/workflow.py` ahora usan las claves `ocelotl_agent_recon`,
`ocelotl_agent_analista`, etc. Se limpió un bloque de tarea huérfano
(`aprobacion_humana_de_hallazgos`) en `config/tasks.yaml` que no tenía ningún
consumidor.

### 3.3 Auditoría UX/visual del panel (`frontend_zotz_web_panel.html`)
Contraste de botones bajo WCAG AA corregido (tokens `--button-primary-bg`,
`--button-success-bg` más oscuros que los originales), color de marca
separado del color de "éxito" (`--brand-color` nuevo), layout del panel más
corto ya no deja hueco vacío (`align-items: start`), foco de teclado visible
en inputs/botones, y el iframe del informe ya no da un salto de blanco puro
("flashbang") al pasar de la UI oscura.

### 3.4 Investigación de mercado (GitHub, herramientas MIT/open-source)
Se analizaron 7 proyectos reales vía la API de GitHub (no memoria):
PentestGPT (15.5k★), HexStrike AI (11.9k★), CAI/archivado (9.8k★), Decepticon
(5.5k★), RedCell (376★, el más cercano en stack: LangGraph+Kali+LiteLLM),
PentestAgent (3.1k★), Ares (73★). Conclusión clave: **ningún proyecto del
ecosistema resuelve bien el enforcement técnico de alcance** — ahí es donde
Zotz puede diferenciarse en vez de solo copiar. Patrón común confirmado:
worker separado del proceso API, ejecución en contenedor/host aislado,
hallazgos estructurados (no texto acumulado), aprobación por acción de
riesgo. Detalle completo de la comparación: buscar en el historial de
conversación la respuesta "Análisis comparativo — ecosistema real de
pentesting/red team con LLM" si se necesita releer el research crudo (no se
persistió aparte; este documento es el resumen accionable).

### 3.5 Fase 1 — de narrador LLM a herramienta que ejecuta y verifica
**Plan aprobado por el usuario, archivado en
`/home/alonso/.claude/plans/flickering-moseying-globe.md`** (léelo si hace
falta el razonamiento completo de diseño). Decisiones de entorno tomadas tras
medir la máquina real (Kali, Docker daemon apagado, RAM ajustada, Redis
disponible como binario, `nmap`/`nuclei` ya instalados):
- **Ejecución de herramientas: directa en el host Kali**, sin Docker
  obligatorio (elegido explícitamente por el usuario ante la pregunta).
- **Cola/worker: Redis + `arq`** (elegido explícitamente, no la opción
  "ligera sin infraestructura nueva" que yo recomendaba por defecto).

Cambios de código (ver sección 4 para el mapa completo de archivos):
- `scope.py::resolve_and_check` — chokepoint técnico: ninguna herramienta
  activa se ejecuta sin que el objetivo resuelva dentro del alcance.
- `tools/executor.py` — `run_nmap`/`run_nuclei` reales, con ese gate de
  scope obligatorio y kill-switch `REDTEAMCREW_ACTIVE_RECON=0`.
- `api/store.py` — tablas `hosts` y `findings` (`origen: herramienta|modelo`).
- `graph/workflow.py` — `reconocimiento_nodo` corre nmap de verdad,
  `analisis_nodo` corre nuclei de verdad sobre los hosts descubiertos,
  `informe_nodo` recibe los hallazgos verificados como contexto aparte.
- `graph/state.py` — `estado_inicial()` como único punto de verdad del shape
  de `AgentState` (antes duplicado en CLI y API).
- `worker.py` (nuevo) — proceso `arq` que ejecuta el grafo fuera del proceso
  API; publica progreso a un **Redis Stream** (`engagement:{id}:events`,
  no pub/sub puro — importante: streams permiten que un cliente SSE que
  conecta tarde igual "se ponga al día" leyendo desde el principio).
- `api/server.py` — reescrito: capa HTTP delgada, sin estado propio, encola
  jobs de `arq`, retransmite el stream de Redis por SSE.
- `pyproject.toml` — deps `arq`, `redis`; entry point `redteamcrew-worker`.

### 3.6 Verificación end-to-end real (no simulada)
Se levantó Redis + worker + API de verdad y se lanzaron 3 engagements reales
contra `127.0.0.1` (objetivo siempre en alcance, sin tocar red externa):
1. Llegó a aprobación humana, se aprobó vía API, falló por **timeout del LLM**
   en la fase de simulación.
2. Al investigar el fallo #1 se encontró un bug real: los hosts/hallazgos ya
   verificados por nmap/nuclei se perdían si una fase posterior fallaba
   (solo se persistían en la rama de éxito). **Corregido**:
   `worker.py::_persistir_hallazgos` ahora corre también en la rama de
   excepción.
3. 2º intento: falló de nuevo por timeout, esta vez en reconocimiento. Se
   midió la causa raíz contra DeepInfra directamente: una completion de
   4096 tokens tarda ~100s reales, y `TIMEOUT` en `llm.py` estaba en 120s —
   al límite incluso antes de esta fase, y los prompts ahora son más largos
   (llevan contexto real de nmap/nuclei). **Corregido**: `TIMEOUT` subido a
   300s en `llm.py`.
4. 3º intento (con el fix): **completó de punta a punta** —
   `status: completed`, informe de 6701 caracteres, nmap descubrió 2 puertos
   reales (`7070/tcp`, `8000/tcp`) en la propia máquina.

## 4. Mapa de archivos (qué es cada cosa, para orientarse rápido)

```
src/redteamcrew/
├── api/
│   ├── server.py       # Capa HTTP. Sin estado propio. Encola jobs, relee SQLite, relee Redis Stream para SSE.
│   ├── store.py         # SQLite: engagements, hosts, findings. Único almacén persistente del sistema.
│   └── __main__.py      # Entry point de `redteamcrew-api`
├── worker.py             # Proceso arq que EJECUTA el grafo de verdad. Publica a Redis Stream.
├── scope.py               # validate_scope (formato) + resolve_and_check (chokepoint técnico de ejecución)
├── graph/
│   ├── state.py          # AgentState (TypedDict) + estado_inicial() (único punto de verdad)
│   └── workflow.py       # Los 7 nodos + build_workflow(). Aquí vive la lógica de negocio real.
├── tools/
│   ├── executor.py       # run_nmap / run_nuclei reales, con gate de scope
│   ├── osint_tool.py     # OSINT pasivo (APIs públicas) — sin cambios esta sesión
│   └── ast_scanner.py    # Escaneo AST de código local — sin cambios esta sesión
├── config/
│   ├── agents.yaml        # Roles de cada agente (claves ocelotl_agent_*)
│   └── tasks.yaml         # Descripciones/salidas esperadas por fase
├── llm.py                 # Cliente DeepInfra directo (urllib). TIMEOUT=300 (recién corregido).
└── main.py                 # CLI (modo automático de aprobación, sin Redis/worker)

frontend_zotz_web_panel.html   # Panel web, sin frameworks
docs/
├── ARQUITECTURA.md            # Cómo funciona el sistema completo (actualizado esta sesión)
├── IDENTITY.md                 # Identidad Zotz/ocelotl_agent (corregido esta sesión)
└── CONTINUIDAD.md              # Este documento
```

## 5. Cómo levantar y verificar (comandos reales, probados)

```bash
cd /home/alonso/red_team_tool/red_team_tool
uv sync

redis-server --daemonize yes               # cola API<->worker
uv run redteamcrew-worker &                # ejecuta el flujo de verdad
uv run redteamcrew-api --port 8123 &       # capa HTTP

curl -s -X POST http://127.0.0.1:8123/api/engagements \
  -H "Content-Type: application/json" \
  -d '{"engagement_name":"t","company_name":"c","authorized_scope":"127.0.0.1","rules_of_engagement":""}'
# -> {"id": "..."}

# Seguir el estado (no hay que esperar en el chat, solo consultar):
uv run python -c "
from redteamcrew.api import store
print(store.obtener('<id>'))
"

# Cuando status == 'esperando_aprobacion':
curl -s -X POST http://127.0.0.1:8123/api/engagements/<id>/approve \
  -H "Content-Type: application/json" \
  -d '{"aprobado": true, "comentario": "ok"}'
```

Calidad de código: `uv run ruff check src tests`, `uv run mypy src/redteamcrew
tests`, `uv run pytest tests/unit -q` (18 tests, todos en verde a fecha de
este documento).

### Variables de entorno relevantes (`.env.example` tiene la lista completa)
`DEEPINFRA_API_KEY`, `LLM_MODEL`, `REDTEAMCREW_API_KEY` (auth opcional),
`REDTEAMCREW_DB` (ruta SQLite), `REDTEAMCREW_SCAN_ROOT` (habilita escaneo AST
de código local), `REDTEAMCREW_REDIS_URL`, `REDTEAMCREW_ACTIVE_RECON`
(`0` desactiva nmap/nuclei globalmente, deja solo OSINT pasivo).

## 6. Pendientes (Estatus de correcciones)

1.  **[RESUELTO] Nuclei no apuntaba a puertos reales.**
    *   *Corrección*: Se refactorizó `_run_nuclei_sobre_hosts` en `graph/workflow.py` para iterar sobre los puertos abiertos descubiertos por nmap e inyectar cada combinación `host:puerto` (o `http://host:puerto` si es web) a `run_nuclei`. La función `run_nuclei` en `executor.py` fue actualizada para permitir especificar un `target_url` preciso sin romper la validación de alcance por host.
2.  **[RESUELTO] El informe final alucinaba hallazgos.**
    *   *Corrección*: Se actualizó `informe_nodo` en `graph/workflow.py` para inyectar una "INSTRUCCIÓN DE SEGURIDAD ABSOLUTA" en el prompt del LLM. Se obliga al modelo a distinguir explícitamente entre hallazgos verificados y narrativa, prohibiendo la invención de vulnerabilidades no presentes en la evidencia técnica inyectada.
3.  **Fase 2 (roadmap, no iniciada)**: loop agéntico real...
4.  **Fase 3 (roadmap, no iniciada)**: validación de explotabilidad real...
5.  **Multi-objetivo**: ...
6.  **Housekeeping menor**: ...

## 7. Decisiones de diseño que un modelo nuevo NO debería deshacer sin saber por qué

- **Redis Streams, no pub/sub puro**, para el canal de eventos SSE — un
  pub/sub normal pierde eventos si el cliente SSE conecta después de que el
  worker ya publicó algo; el stream permite leer desde el principio.
- **Ejecución de herramientas en el host, no en contenedor** — decisión
  explícita del usuario dado el entorno real (ya es Kali, Docker no estaba
  corriendo). Si se cambia de máquina/entorno, reconsiderar.
- **`TIMEOUT = 300` en `llm.py`** está respaldado por una medición real
  (~100s para una completion de 4096 tokens), no es un número arbitrario —
  no bajarlo sin volver a medir.
- **Kill-switches por env var** (`REDTEAMCREW_ACTIVE_RECON`,
  `REDTEAMCREW_SCAN_ROOT`) siguen el mismo patrón en todo el proyecto:
  cualquier capacidad que toque el mundo real (red, filesystem) está
  deshabilitada por defecto salvo configuración explícita del operador.
- **`origen: 'herramienta' | 'modelo'`** en la tabla `findings` es el
  mecanismo central para separar verificado de inferido — cualquier fix al
  problema de alucinación (punto 2 de la sección 6) debe apoyarse en este
  campo, no introducir uno nuevo.
