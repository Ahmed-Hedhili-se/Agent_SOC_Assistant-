# Agentic SOC Assistant

A multi-agent Security Operations Center (SOC) assistant built with **LangGraph** and a **Model Context Protocol (MCP)**-style tool layer. It automates alert triage, log investigation, CTI enrichment, MITRE ATT&CK mapping, and incident report drafting — while keeping a strict **human-in-the-loop (HITL)** boundary around every action that could change the real environment.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![LangGraph](https://img.shields.io/badge/orchestration-LangGraph-1f6feb)
![FastAPI](https://img.shields.io/badge/HITL%20API-FastAPI-009688)

**Benchmarked result:** grounding the ATT&CK mapper in retrieval raises exact technique accuracy from 38% to **62%** on 50 labelled ATT&CK procedure examples (gpt-oss:20b, McNemar p = 0.008), and the gain replicates across three self-hosted models — [see the benchmark](#benchmark-attck-technique-mapping).

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

Does retrieval-grounded mapping actually beat asking the model directly? `eval/attck_benchmark.py` measures it.

**Setup.** Ground truth comes from MITRE ATT&CK's own procedure examples (release v15.1, the same release the RAG index uses): each real-world procedure description becomes an alert, and the technique it documents is the expected answer. Citations, links and technique IDs are stripped from the text, so the answer never leaks. The dataset is 50 examples covering 50 distinct techniques (35 of them sub-techniques) and is committed in `data/benchmarks/attck_procedures.json`. Scoring is reported at two levels: **exact** (T1059.001 must match T1059.001) and **parent** (T1059.001 counts as T1059). Neither prompt contains an example technique ID, since small models copy one verbatim.

### Retrieval vs. the same model alone

| System (gpt-oss:20b) | Exact P | Exact R | Exact F1 | Parent R | Median latency |
|---|---|---|---|---|---|
| `baseline` — one direct LLM prompt | 0.36 | 0.38 | 0.36 | 0.62 | 5.6 s |
| `mapper` — ATT&CK agent (RAG + LLM) | **0.54** | **0.62** | **0.56** | **0.78** | 7.5 s |
| `pipeline` — full multi-agent graph | 0.52 | 0.62 | 0.55 | 0.76 | 35.6 s |

The gain holds across three self-hosted models of different sizes and families (exact recall, 50 paired examples, two-sided exact McNemar test):

| Model | Baseline | Mapper (RAG) | p (exact) | p (parent) |
|---|---|---|---|---|
| gpt-oss:20b | 38% | **62%** | 0.008 | 0.039 |
| glm-4.7-flash (q4) | 14% | **54%** | <0.0001 | 0.019 |
| qwen3:8b | 2% | **52%** | <0.0001 | <0.0001 |

### What the numbers say

- **Retrieval significantly improves exact technique identification for every model tested.** The effect is largest where the model's own ATT&CK knowledge is weakest: with retrieval, all three models land in a 52–62% band regardless of where they started.
- **Most of the gain is ID precision, not comprehension.** gpt-oss:20b already identified the right parent technique 62% of the time on its own; retrieval mainly converts "roughly the right family" into the exact sub-technique ID.
- **The full pipeline matched the mapper agent exactly** (31/50 both, p = 1.0) at ~5x the latency. For this task the accuracy comes from the retrieval-grounded agent, not from the surrounding agents.
- **Retrieval is not free.** In 1–4 cases per model the baseline was right where the RAG-grounded agent was wrong, i.e. retrieved context can mislead. Filtering retrieved documents by relevance is the obvious next step.

### Limitations

- 50 examples per system: differences of a few points are within noise, and only the large gaps above are significant.
- ATT&CK procedure descriptions are curated CTI prose, not raw SIEM logs. These numbers are an upper bound on messy production data.
- Retrieval runs over the official technique descriptions, matched in domain and vocabulary to the test prose.
- The pipeline row is one model, N=50. The benchmark scores **ATT&CK mapping only**: triage, correlation, synthesis and report quality are not measured, so this says nothing about whether the other agents help at *their* jobs.
- LLM sampling is non-deterministic; single runs per cell, no repeats.

### Reproduce

```bash
cd soc-assistant
export SOC_ASSISTANT_MOCK_EMBEDDINGS=0
python -m rag.indexer                                     # build the ATT&CK index once
python -m eval.attck_benchmark run --system baseline
python -m eval.attck_benchmark run --system mapper
python -m eval.attck_benchmark compare --a baseline --b mapper
python -m eval.attck_benchmark report
```

Raw per-example predictions and run summaries for every result above are in `eval/results/`. `python -m eval.attck_benchmark build --n 150` rebuilds a larger dataset, and `SOC_ASSISTANT_MODEL=<id>` points every role at another model.

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
