# Identity: Zotz

## 1. Etymology and Origin
- **Root Term:** *Zotz* (also documented as *Sotz'* in modern Mayan orthography).
- **Literal Meaning:** Bat.
- **Ethnohistorical Context:** Direct reference to Mayan cosmology and the Dresden Codex. The bat figure is associated with the underworld (*Xibalbá*) and the nocturnal cycle.

## 2. Tactical Rationale
The name *Zotz* functions as an operational metaphor for the framework:
- **Echolocation:** Represents passive reconnaissance capabilities, gathering intelligence without emitting active, detectable signals.
- **Low-Profile Operations:** Evokes the "low flight" technique, emphasizing evasion of defensive monitoring systems.
- **Nocturnal Persistence:** Reflects the ability to operate persistently and effectively within the "shadows" of a target environment.

## 3. Identity Specifications
- **Brand/Product Identifier:** `Zotz` — the umbrella name shown to operators (panel web, README, informe).
- **Technical Package Identifier:** `redteamcrew` (lowercase, `pyproject.toml`). The installable
  binaries are `redteamcrew`, `redteamcrew-api` and `run_crew` — there is currently no `zotz`
  binary. If a fully-branded CLI entry point (`zotz`) is desired, it should be added as a new
  `[project.scripts]` alias rather than a rename, to avoid churn on existing automation.
- **Logging Prefix:** `[zotz-core]` — implemented (`redteamcrew/utils/logger.py`). `zotz-beacon`
  is a **planned** prefix for a future persistent/beacon-style component; nothing in the current
  LangGraph node set emits it yet.
- **Visual Representation (Isotype Suggestion):** Minimalist, angular geometric silhouette of a bat inspired by Mayan architectural motifs or epigraphic glyphs. Designed for high contrast in terminal (ANSI) color schemes and small-format avatar assets (e.g., repository branding).

## 4. Agent Naming Convention

- **Root Term:** *Ocelotl* (Nahuatl orthography; commonly rendered *ocelot* in English).
- **Literal Meaning:** Ocelot/jaguar — a stealth predator associated in Mesoamerican (Aztec/Nahua) tradition with the *Ocelotl* warrior class, known for nocturnal ambush hunting and camouflage rather than open confrontation.
- **Tactical Rationale:** Complements the *Zotz* identity (passive reconnaissance/echolocation) with an operational metaphor for the active/investigative agent roles — precision tracking, patient stalking of a target before engaging, and controlled, deliberate strikes rather than brute force.
- **Identifier:** Each phase's agent persona is keyed as `ocelotl_agent_<rol>` in
  `src/redteamcrew/config/agents.yaml`, referenced from the `AGENT_*` constants in
  `src/redteamcrew/graph/workflow.py`, and cross-referenced (informationally) from the `agent:`
  field of each task in `src/redteamcrew/config/tasks.yaml`:
  `ocelotl_agent_recon`, `ocelotl_agent_analista`, `ocelotl_agent_explotador`,
  `ocelotl_agent_estratega`, `ocelotl_agent_fiscal`, `ocelotl_agent_cronista`.
- **Status:** ✅ Implemented (LangGraph architecture). There is no `crew.py` in the current
  codebase — that file belonged to a prior CrewAI-based implementation and was removed when the
  project migrated to LangGraph (`workflow.py` + direct LLM calls). `zotz` remains the umbrella
  product identity while `ocelotl_agent` is the per-agent key namespace inside `agents.yaml`.
