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

## Ejecución

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
```

Al terminar guarda el informe final en `./outputs/<engagement>/informe.md` y lo
imprime en pantalla. `--help` muestra todas las opciones.

El flujo recorre las fases del engagement:

`Reconocimiento → Análisis de Vulnerabilidades → Validación → Aprobación Humana → Simulación Adversarial → Revisión → Informe`

Ejecución en bucle de la fase de reconocimiento hasta alcanzar suficiencia o
el máximo de iteraciones, usando LangGraph.

## Estructura

```
src/redteamcrew/
├── config/
│   ├── agents.yaml          # Roles/objetivos/perfiles de cada fase
│   ├── tasks.yaml           # Descripciones y salidas esperadas
│   └── prompts.py           # Carga e interpolación de prompts desde YAML
├── graph/
│   ├── state.py             # Estado del grafo (AgentState)
│   └── workflow.py          # Nodos y grafo LangGraph
├── tools/
│   ├── ast_scanner.py       # Análisis estático (AST) de código Python
│   └── osint_tool.py        # Consultas OSINT a APIs públicas
├── llm.py                   # Cliente LLM directo para DeepInfra (urllib)
├── main.py                  # Punto de entrada
└── utils/logger.py          # Logging estructurado (structlog)
```

## Herramientas

- `osint_search(query, operation)`: reconocimiento pasivo (DNS, subdominios,
  certificados, IP, CVE, CISA KEV, OTX).
- `scan_ast(path)`: análisis estático de código Python (funciones peligrosas,
  inyección SQL, secretos hardcodeados).

Ambas son funciones puras reutilizables por los nodos del grafo.

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
