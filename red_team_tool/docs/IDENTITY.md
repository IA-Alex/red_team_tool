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
- **Package/Binary Identifier:** `zotz` (lowercase, standardized for CLI executables).
- **Logging/Agent Prefix:** `[zotz-core]`, `[zotz-beacon]`.
- **Visual Representation (Isotype Suggestion):** Minimalist, angular geometric silhouette of a bat inspired by Mayan architectural motifs or epigraphic glyphs. Designed for high contrast in terminal (ANSI) color schemes and small-format avatar assets (e.g., repository branding).

## 4. Agent Naming Convention

- **Root Term:** *Ocelotl* (Nahuatl orthography; commonly rendered *ocelot* in English).
- **Literal Meaning:** Ocelot/jaguar — a stealth predator associated in Mesoamerican (Aztec/Nahua) tradition with the *Ocelotl* warrior class, known for nocturnal ambush hunting and camouflage rather than open confrontation.
- **Tactical Rationale:** Complements the *Zotz* identity (passive reconnaissance/echolocation) with an operational metaphor for the active/investigative agent roles — precision tracking, patient stalking of a target before engaging, and controlled, deliberate strikes rather than brute force.
- **Planned Identifier:** Individual agents are to be named with the `ocelotl_agent` prefix (e.g., `ocelotl_agent_recon`, `ocelotl_agent_analista`, following the same slot pattern as the current `zotz_*` methods in `crew.py`).
- **Status:** ✅ Implemented. `src/redteamcrew/crew.py` defines agents under the `ocelotl_agent_*` prefix (`ocelotl_agent_recon`, `ocelotl_agent_analista`, `ocelotl_agent_explotador`, `ocelotl_agent_estratega`, `ocelotl_agent_fiscal`, `ocelotl_agent_cronista`). `zotz` remains the umbrella project/package identity while `ocelotl_agent` is the per-agent identifier namespace.
