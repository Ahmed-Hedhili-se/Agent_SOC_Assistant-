# Benchmark run results

Raw output of `eval/attck_benchmark.py`, one directory per run:

- `summary.json` — aggregate metrics for the run
- `predictions.jsonl` — one line per example: expected vs predicted technique IDs, per-example scores, latency, error

Directory names are `<UTC timestamp>_<system>_<model>`.

| Run | System | Model | N |
|---|---|---|---|
| 20260911T192638Z | mapper | gpt-oss:20b | 50 |
| 20260911T200037Z | pipeline | gpt-oss:20b | 50 |
| 20260911T203724Z | mapper | qwen3:8b | 50 |
| 20260911T211143Z | mapper | glm-4.7-flash:q4_K_M | 50 |
| 20260912T132202Z | baseline | gpt-oss:20b | 50 |
| 20260912T132806Z | baseline | qwen3:8b | 50 |
| 20260912T133313Z | baseline | glm-4.7-flash:q4_K_M | 50 |

All runs used the dataset in `data/benchmarks/attck_procedures.json` (ATT&CK v15.1,
50 examples, 50 distinct techniques) against self-hosted Ollama models on a
24 GB NVIDIA A40 vGPU, with real sentence-transformer embeddings and the
ATT&CK Chroma index built by `python -m rag.indexer`.

Note on the baseline runs: an earlier set (not kept) used a prompt containing a
concrete technique ID as a formatting example, which small models copied
verbatim (qwen3:8b emitted it for 10 of 50 alerts). The example ID was removed
and all three baselines were re-run; the runs above are the corrected ones.

Reproduce or extend:

    python -m eval.attck_benchmark report
    python -m eval.attck_benchmark compare --a baseline --b mapper
