# Agentic SOC Assistant

A multi-agent Security Operations Center (SOC) assistant built with **LangGraph** and a **Model Context Protocol (MCP)**-style tool layer. It automates alert triage, log investigation, CTI enrichment, MITRE ATT&CK mapping, and incident report drafting — while keeping a strict **human-in-the-loop (HITL)** boundary around every action that could change the real environment.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![LangGraph](https://img.shields.io/badge/orchestration-LangGraph-1f6feb)
![FastAPI](https://img.shields.io/badge/HITL%20API-FastAPI-009688)

## Design philosophy

**Augmentation, not autonomy.** Agents collect evidence, correlate logs, enrich with threat intelligence, map to ATT&CK, and draft reports. **No agent can change the real environment.** Every remediation tool (`isolateHost`, `disableUserAccount`, `blockIPFirewall`, `createTicket`) requires an `approved_by` field that only the HITL decision endpoint can set — enforced in code at the tool layer, not just in prompts.

## Architecture

![Target architecture](docs/architecture_diagram.png)

```text
triage ──► [ log_investigator | cti_enrichment | attck_mapper ] ──► reasoning_synthesis ──► report_generator
                    (parallel LangGraph superstep)                                                │
                                                                          ─ ─ HITL boundary ─ ─ ─ ┤
                                                                                                  ▼
                                                         analyst dashboard: approve / modify / reject / escalate
                                                                                                  │
                                                           ┌──────────────────────────────────────┴───┐
                                                           ▼                                          ▼
                                                  RAG feedback ledger                     DPO preference pairs
                                                                                     (offline per-role fine-tuning)
```

| Agent | Responsibility |
|---|---|
| **Triage** | Severity score, false-positive probability, category, authorized-activity check |
| **Log Investigator** | Correlates SIEM events and process trees into a timeline of anomalies |
| **CTI Enrichment** | IP/hash reputation lookups, shared-infrastructure discounting, RAG-retrieved CTI context |
| **ATT&CK Mapper** | Candidate techniques from RAG, tactic chain, kill-chain position, predicted next tactics |
| **Reasoning & Synthesis** | Reconciles all agent outputs into a verdict; escalation policy enforced as code |
| **Report Generator** | Executive summary, evidence chain, technique cards, remediation proposals (always approval-gated) |

### Key capabilities

- **Conditional routing** — identity-only alerts (e.g. `impossible_travel`) skip log investigation; endpoint alerts fan out to three parallel agents.
- **Failure recovery** — each node is retried once, then recorded in `agents_failed` / `missing_evidence` instead of crashing the graph.
- **Fast path** — critical (severity ≥ 9.0), high-confidence (≥ 0.90) triage results trigger an immediate side-channel notification.
- **Privacy guard** — agents that handle raw internal logs refuse to fall back to a hosted LLM (`PrivacyConstraintViolation`).
- **4-store RAG knowledge base** — MITRE ATT&CK and CTI reports (Chroma), IOC exclusivity and org assets (SQLite), each with a built-in fallback so the pipeline runs offline.
- **HITL dashboard & SLA** — FastAPI backend with a built-in analyst UI and per-severity response deadlines.
- **Continual improvement** — analyst corrections feed a RAG feedback ledger and a DPO preference-pair dataset; `training/dpo_train.py` fine-tunes a role offline and promotes the checkpoint only if the held-out reward margin improves.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design and [docs/report.pdf](docs/report.pdf) for the evaluation report.

## Project structure

```text
SOC_Assistant/
├── docs/                    # Architecture notes, diagram, evaluation report (LaTeX + PDF)
└── soc-assistant/
    ├── agents/              # The six LangGraph agent nodes
    ├── config/              # models.yaml (LLM per role), thresholds, tool budgets, DPO settings
    ├── data/alerts/         # Sample alerts used by the demo and the tests
    ├── deploy/              # Optional vLLM self-hosting script + systemd unit
    ├── eval/                # Override-rate metrics and per-role model ablation harness
    ├── hitl/                # FastAPI HITL backend + static analyst dashboard (hitl/ui/)
    ├── mcp_tools/           # Tool layer: read_only, rag, and approval-gated write tools
    ├── models/, schemas/    # Pydantic models for alerts and agent outputs
    ├── orchestrator/        # LangGraph StateGraph: routing, retries, fast path
    ├── rag/                 # Vector / key-value stores and the ATT&CK indexer
    ├── review/feedback/     # Analyst feedback loops (RAG ledger, DPO preference pairs)
    ├── state/               # Shared graph state schema
    ├── training/            # Offline per-role DPO fine-tuning
    ├── tests/               # pytest suite (runs fully offline)
    ├── run_pipeline.py      # End-to-end demo runner
    └── requirements.txt
```

## Getting started

### Prerequisites

- Python 3.11+
- For live inference: an OpenAI-compatible endpoint. The default config (`soc-assistant/config/models.yaml`) points every role at a local [Ollama](https://ollama.com) server running `gpt-oss:20b`, with an optional hosted Grok fallback (`GROK_API_KEY`).
- No LLM at all is needed for the demo in mock mode or for the test suite.

### Installation

```bash
git clone https://github.com/Ahmed-Hedhili-se/Agent_SOC_Assistant-.git
cd Agent_SOC_Assistant-
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r soc-assistant/requirements.txt
```

The DPO packages at the bottom of `requirements.txt` (`torch`, `transformers`, `trl`, …) are only needed for `training/dpo_train.py`.

### Run the pipeline

```bash
cd soc-assistant

# Offline demo: deterministic mock LLM, no server required
python run_pipeline.py --mock-llm

# Live inference against the endpoints in config/models.yaml
# (with `ollama serve` running, pull the model once: `ollama pull gpt-oss:20b`)
python run_pipeline.py --alert-id ALT-2026-002
```

### Review investigations in the HITL dashboard

```bash
cd soc-assistant
uvicorn hitl.api:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000> for the analyst dashboard, or <http://127.0.0.1:8000/docs> for the interactive API.

### Optional: index the real MITRE ATT&CK corpus

```bash
cd soc-assistant
SOC_ASSISTANT_MOCK_EMBEDDINGS=0 python -m rag.indexer
```

### Run the tests

```bash
cd soc-assistant
pytest -v
```

The suite runs fully offline (mock embeddings + mock LLM) and covers graph routing, parallel fan-out regressions, the approval gate on write tools, RAG wiring, the HITL decision flow, SLA deadlines, and the DPO data pipeline.

## Benchmark: ATT&CK technique mapping

`eval/attck_benchmark.py` measures how accurately the system maps security events to MITRE ATT&CK techniques. Ground truth comes from ATT&CK's own procedure examples (pinned to release v15.1): each real-world procedure description becomes an alert, and its technique ID is the answer. Citations, links and technique IDs are stripped so the answer never leaks. The dataset (50 examples, 50 distinct techniques) is in `data/benchmarks/attck_procedures.json`.

Three systems are compared using the same model:

| System | What runs |
|---|---|
| `baseline` | A single direct LLM prompt, no tools or retrieval |
| `mapper` | The ATT&CK Mapper agent (RAG over the ATT&CK knowledge base + LLM) |
| `pipeline` | The full multi-agent graph (the mapper also uses triage's category) |

```bash
cd soc-assistant
python -m eval.attck_benchmark run --system baseline
python -m eval.attck_benchmark run --system mapper
python -m eval.attck_benchmark report     # table of all completed runs
```

Results (precision, recall and F1 at exact and parent-technique level, plus latency) are written to `eval/results/`.

## Configuration

| File | Purpose |
|---|---|
| `config/models.yaml` | Endpoint, model and fallback per agent role |
| `config/thresholds.yaml` | Fast-path, escalation and SLA thresholds |
| `config/tool_budgets.yaml` | Per-role MCP tool-call caps |
| `config/dpo.yaml` | DPO training hyper-parameters and promotion gate |

| Environment variable | Effect |
|---|---|
| `SOC_ASSISTANT_MOCK_LLM=1` | Deterministic mock completions instead of calling an LLM |
| `SOC_ASSISTANT_MODEL=<id>` | Override the primary model of every role (e.g. for model comparisons) |
| `SOC_ASSISTANT_MOCK_EMBEDDINGS=1` | Zero-vector embedder instead of downloading a sentence-transformer |
| `GROK_API_KEY` | API key for the hosted Grok fallback |

## Current limitations

- SIEM, EDR and threat-intel tools return deterministic mock data; write tools are simulated.
- Per-role tool budgets are configured but not yet enforced at call time.
- RAG corrections are logged to a ledger; live re-embedding into Chroma is a planned step.

## Author

**Ahmed Hedhili** — [GitHub @Ahmed-Hedhili-se](https://github.com/Ahmed-Hedhili-se)
