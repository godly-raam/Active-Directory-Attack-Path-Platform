# ap-engine — Active Directory Attack-Path Engine

`ap-engine` ingests a SharpHound/BloodHound export, builds a directed graph of
Active Directory relationships, finds escalation paths from a foothold to
Tier 0, scores them deterministically, and (optionally) asks an LLM to rank and
explain them in plain English. It then renders a Markdown, HTML, and/or JSON
report.

It is the analysis half of the AD cyber-range project in the parent directory;
it runs entirely on the local attack box and never touches the Azure range.

## Why it exists

BloodHound shows you a graph. `ap-engine` answers the operator's actual
question: *given this foothold, what is the most practical route to Domain
Admin, and how do I fix it?* The deterministic scorer always runs, so the tool
is useful with no API key and no network access. The LLM layer is an optional
narrative/re-ranking step, not a requirement.

## Install

```bash
# from the attack-path-engine directory
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,llm]"
```

Python 3.10+ is required. `anthropic` is optional at runtime: if it is missing
or no key is configured, the engine silently falls back to deterministic
ranking.

## Usage

```bash
# Point at a SharpHound zip, a directory of JSON, or a single JSON file.
ap-engine analyze --bloodhound ./bloodhound.zip --out ./reports

# Deterministic only — no LLM, no API key needed.
ap-engine analyze -b ./bloodhound_dir --offline --print

# Treat specific accounts as already compromised (SAM names or SIDs).
ap-engine analyze -b ./bloodhound_dir --owned carolclark,svc_dcsync

# Choose output formats.
ap-engine analyze -b ./bloodhound_dir -f markdown,html,json
```

Without `--owned`, every enabled non-high-value user is treated as a plausible
starting point. This models "the operator phished any regular user."

### Outputs

| File | Contents |
|------|----------|
| `attack-path-report.md` | Full report: summary, ranked paths, findings |
| `attack-path-report.html` | Same, styled for a browser/portfolio |
| `attack-path-report.json` | Machine-readable result for automation |

## How it works

```
BloodHound JSON/zip
        │
        ▼
   ingest.py      normalise several SharpHound shapes into Node/Edge
        │
        ▼
   graph.py       build DiGraph, resolve SPNs, propagate OU ACEs, mark Tier 0
        │
   ┌────┴─────────────┐
   ▼                  ▼
 paths.py          findings.py     Dijkstra from footholds; attribute weaknesses
   │                  │            (Kerberoast, AS-REP, delegation, ADCS…)
   └────┬─────────────┘
        ▼
  llm_ranker.py    deterministic score, then optional LLM narrative
        │
        ▼
   report.py       Markdown / HTML / JSON
```

### Deterministic scoring

Every edge carries an *effort* weight (lower = easier to abuse), e.g. `DCSync`
= 0.3, `GenericAll` = 0.8, `CanRDP` = 2.6. Paths are the cheapest routes found
with Dijkstra; ACEs inherited through an OU/container get a ×1.25 containment
penalty so inherited rights rank below direct ones. Scores map to bands:
`trivial` ≤ 1.5, `easy` ≤ 3.0, `moderate` ≤ 6.0, else `hard`.

### LLM ranking (optional)

When `USER_LLM_API_KEY` is set and `AP_ENGINE_OFFLINE` is not enabled, the
candidate paths plus supporting findings are sent to the model, which re-ranks
them by real-world exploitability and writes the explanation, prerequisites,
and mitigations. Any API/parse failure degrades gracefully to the
deterministic result — the report is always produced.

## Configuration

Copy `.env.example` to `.env` (git-ignored) and edit. All variables are
project-scoped:

| Variable | Default | Purpose |
|----------|---------|---------|
| `USER_LLM_API_KEY` | _(none)_ | Your own key. No key ⇒ deterministic mode. |
| `USER_LLM_BASE_URL` | `https://api.anthropic.com` | Provider endpoint |
| `USER_LLM_MODEL` | `claude-sonnet-5` | Model name |
| `AP_ENGINE_OFFLINE` | `0` | `1`/`true` forces deterministic mode |
| `AP_ENGINE_TOP_N` | `15` | Max candidate paths sent to the LLM (cost control) |

> **Credential hygiene.** The engine reads only `USER_LLM_*`/`AP_ENGINE_*`. It
> must never read the coding agent's own `MCAI_LLM_*` variables, and a test
> (`test_config.py::test_source_never_reads_platform_vars`) enforces that no
> module does so.

## Tests

```bash
python3 -m pytest
```

The suite (50 tests) runs fully offline against fixture BloodHound data in
`tests/fixtures/bloodhound/` and covers ingestion, graph construction, ACE
propagation, SPN resolution, path finding, findings, deterministic and LLM
ranking (with a stubbed client), report rendering, and the CLI.

## Project layout

```
src/ap_engine/
  model.py      Node / Edge / Dataset dataclasses
  config.py     USER_LLM_* config + .env loader
  scoring.py    edge weights, rating bands, MITRE map
  ingest.py     SharpHound JSON/zip normalisation
  graph.py      DiGraph build, SPN resolution, ACE propagation, Tier 0 marking
  paths.py      Dijkstra path search and per-target trimming
  findings.py   attribute-based misconfiguration findings
  llm_ranker.py deterministic + LLM ranking
  analyze.py    orchestration
  report.py     Markdown / HTML / JSON rendering
  cli.py        argparse entry point (console script: ap-engine)
  templates/    report.md.j2, report.html.j2
```

## Scope and ethics

This tool analyses an isolated lab environment that the operator owns and
controls. It is a defensive/educational aid for understanding and remediating
AD misconfigurations. Do not run it against systems you are not authorised to
assess.
