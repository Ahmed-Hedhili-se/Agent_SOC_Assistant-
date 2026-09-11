"""
eval/attck_benchmark.py

ATT&CK technique-mapping benchmark.

Ground truth comes from MITRE ATT&CK procedure examples: every "uses"
relationship in enterprise-attack.json pairs a real-world procedure
description with the technique it demonstrates. Each description becomes an
alert's raw_log, and its technique ID is the expected answer. Citations,
links and explicit technique IDs are stripped so the answer never leaks.
The ATT&CK release is pinned (see rag/indexer.py) so the dataset and the
RAG index use the same technique IDs.

Three systems are scored on the same dataset, all with the model that
config/models.yaml (or SOC_ASSISTANT_MODEL) assigns:
  - baseline: one direct LLM prompt, no tools or retrieval
  - mapper:   the ATT&CK Mapper agent alone (RAG + LLM)
  - pipeline: the full multi-agent graph; the mapper sees triage's category

Metrics are reported at two levels: exact (T1059.001 must match T1059.001)
and parent (T1059.001 counts as T1059).

Usage (from soc-assistant/):
    python -m eval.attck_benchmark build --n 50
    python -m eval.attck_benchmark run --system baseline
    python -m eval.attck_benchmark run --system mapper
    python -m eval.attck_benchmark run --system pipeline
    python -m eval.attck_benchmark report
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rag.indexer import ATTCK_URL  # noqa: E402  (same pinned release as the RAG index)

DEFAULT_DATASET = PROJECT_ROOT / "data" / "benchmarks" / "attck_procedures.json"
RESULTS_DIR = PROJECT_ROOT / "eval" / "results"

_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SOURCE_TYPES = {"intrusion-set", "malware", "tool", "campaign"}
_GROUND_TRUTH_KEYS = {"expected_techniques", "technique_name", "attck_relationship_id"}


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

def clean_description(text: str) -> str:
    """Turn an ATT&CK procedure description into plain alert text."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)  # markdown link -> link text
    text = re.sub(r"<[^>]+>", "", text)                     # <code> and other tags
    text = _TECHNIQUE_ID_RE.sub("", text)                   # never leak the answer
    return re.sub(r"\s+", " ", text).strip()


def _is_active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _external_id(obj: dict) -> Optional[str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build_dataset(bundle: dict, n: int = 50, seed: int = 42, min_chars: int = 40) -> list[dict]:
    """Sample *n* procedure examples (at most one per technique) from an
    ATT&CK STIX bundle, reproducibly for a given *seed*."""
    objects = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objects if "id" in o}
    techniques = {
        o["id"]: o for o in objects
        if o.get("type") == "attack-pattern" and _is_active(o) and _external_id(o)
    }

    candidates = []
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "uses":
            continue
        if not _is_active(rel):
            continue
        technique = techniques.get(rel.get("target_ref"))
        source = by_id.get(rel.get("source_ref"))
        if technique is None or source is None or source.get("type") not in _SOURCE_TYPES:
            continue
        text = clean_description(rel.get("description", ""))
        if len(text) >= min_chars:
            candidates.append((rel["id"], technique, text))

    candidates.sort(key=lambda c: c[0])
    random.Random(seed).shuffle(candidates)

    dataset: list[dict] = []
    seen: set[str] = set()
    for rel_id, technique, text in candidates:
        technique_id = _external_id(technique)
        if technique_id in seen:
            continue
        seen.add(technique_id)
        dataset.append({
            "alert_id":              f"ATTCK-BENCH-{len(dataset) + 1:03d}",
            "source":                "SIEM",
            "category":              "unknown",
            "severity":              5.0,
            "timestamp":             "2026-01-01T00:00:00Z",
            "raw_log":               text,
            "expected_techniques":   [technique_id],
            "technique_name":        technique.get("name"),
            "attck_relationship_id": rel_id,
        })
        if len(dataset) >= n:
            break
    return dataset


def _load_bundle(source: str) -> dict:
    if source.startswith(("http://", "https://")):
        import requests
        print(f"Downloading {source} ...")
        response = requests.get(source, timeout=120)
        response.raise_for_status()
        return response.json()
    return json.loads(Path(source).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def normalize_ids(ids: Iterable) -> list[str]:
    """Extract unique, upper-cased technique IDs, preserving order."""
    out: list[str] = []
    for item in ids or []:
        match = _TECHNIQUE_ID_RE.search(str(item).upper())
        if match and match.group() not in out:
            out.append(match.group())
    return out


def _parent(technique_id: str) -> str:
    return technique_id.split(".")[0]


def score_prediction(predicted: Iterable, expected: Iterable) -> dict:
    pred = normalize_ids(predicted)
    exp = normalize_ids(expected)
    result: dict = {"n_predicted": len(pred)}
    for level, key in (("exact", lambda t: t), ("parent", _parent)):
        p = {key(t) for t in pred}
        e = {key(t) for t in exp}
        tp = len(p & e)
        precision = tp / len(p) if p else 0.0
        recall = tp / len(e) if e else 0.0
        f1 = 2 * precision * recall / (precision + recall) if tp else 0.0
        result[level] = {"precision": precision, "recall": recall, "f1": f1}
    return result


def summarize(rows: list[dict], **meta) -> dict:
    def mean(values: list[float]) -> float:
        return round(statistics.fmean(values), 3) if values else 0.0

    latencies = [r["latency_s"] for r in rows]
    return {
        **meta,
        "n":                len(rows),
        "exact_precision":  mean([r["exact"]["precision"] for r in rows]),
        "exact_recall":     mean([r["exact"]["recall"] for r in rows]),
        "exact_f1":         mean([r["exact"]["f1"] for r in rows]),
        "parent_precision": mean([r["parent"]["precision"] for r in rows]),
        "parent_recall":    mean([r["parent"]["recall"] for r in rows]),
        "parent_f1":        mean([r["parent"]["f1"] for r in rows]),
        "avg_predicted":    mean([r["n_predicted"] for r in rows]),
        "empty_rate":       mean([float(r["n_predicted"] == 0) for r in rows]),
        "errors":           sum(1 for r in rows if r["error"]),
        "latency_mean_s":   mean(latencies),
        "latency_median_s": round(statistics.median(latencies), 2) if latencies else 0.0,
        "created_at":       datetime.now(timezone.utc).isoformat(),
    }


def format_table(summaries: list[dict]) -> str:
    lines = [
        "| System | Model | N | Exact P | Exact R | Exact F1 | Parent R | Parent F1 | Avg #pred | Errors | Median latency (s) |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for s in summaries:
        lines.append(
            f"| {s['system']} | {s['model']} | {s['n']} | {s['exact_precision']:.2f} | "
            f"{s['exact_recall']:.2f} | {s['exact_f1']:.2f} | {s['parent_recall']:.2f} | "
            f"{s['parent_f1']:.2f} | {s['avg_predicted']:.1f} | {s['errors']} | {s['latency_median_s']:.1f} |"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Systems under test
# ---------------------------------------------------------------------------

_BASELINE_PROMPT = """You are a MITRE ATT&CK analyst. Map the security event below to the MITRE ATT&CK Enterprise technique IDs it demonstrates, using sub-technique IDs (e.g. T1059.001) where applicable.

Respond with ONLY a JSON object in this exact format, no explanations:
{"technique_ids": ["<technique_id>"]}"""


def _public_alert(alert: dict) -> dict:
    """The alert as the system under test sees it -- ground truth removed."""
    return {k: v for k, v in alert.items() if k not in _GROUND_TRUTH_KEYS}


def _run_baseline(alert: dict) -> list[str]:
    from langchain_core.messages import HumanMessage, SystemMessage

    from agents._llm import parse_json_response
    from config.provider import get_provider

    response = get_provider("attck_mapper").invoke([
        SystemMessage(content=_BASELINE_PROMPT),
        HumanMessage(content=f"Security event:\n\n{alert['raw_log']}"),
    ])
    return parse_json_response(response.content).get("technique_ids") or []


def _run_mapper(alert: dict) -> list[str]:
    from agents.attck_mapper import run_attck_mapper

    state = {"alert_raw": _public_alert(alert), "alert_category": None, "triage_output": None}
    return run_attck_mapper(state)["attck_output"]["technique_ids"]


_graph = None


def _run_pipeline(alert: dict) -> list[str]:
    global _graph
    from orchestrator.graph import build_soc_graph

    if _graph is None:
        _graph = build_soc_graph()

    public = _public_alert(alert)
    state = {
        "alert_id":            public["alert_id"],
        "alert_raw":           public,
        "alert_category":      None,  # let the mapper use triage's category
        "alert_timestamp":     public["timestamp"],
        "agents_activated":    [],
        "agents_completed":    [],
        "agents_failed":       [],
        "missing_evidence":    [],
        "audit_log":           [],
        "tool_calls_count":    {},
        "confidence_score":    0.0,
        "escalation_flag":     False,
        "pipeline_start_time": datetime.now(timezone.utc).isoformat(),
    }
    config = {"configurable": {"thread_id": f"bench-{public['alert_id']}-{time.time_ns()}"}}
    final = _graph.invoke(state, config=config)
    if "attck_mapper" in (final.get("agents_failed") or []):
        raise RuntimeError("attck_mapper failed after retry")
    return (final.get("attck_output") or {}).get("technique_ids") or []


SYSTEMS: dict[str, Callable[[dict], list[str]]] = {
    "baseline": _run_baseline,
    "mapper":   _run_mapper,
    "pipeline": _run_pipeline,
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _model_label() -> str:
    if os.environ.get("SOC_ASSISTANT_MOCK_LLM") == "1":
        return "mock"
    if os.environ.get("SOC_ASSISTANT_MODEL"):
        return os.environ["SOC_ASSISTANT_MODEL"]
    from config import load_yaml
    return load_yaml("models.yaml").get("attck_mapper", {}).get("model_id", "unknown")


def run_benchmark(
    system: str,
    dataset_path: Path = DEFAULT_DATASET,
    limit: Optional[int] = None,
    results_dir: Path = RESULTS_DIR,
) -> Path:
    """Run *system* over the dataset; write predictions.jsonl and summary.json."""
    alerts = json.loads(Path(dataset_path).read_text(encoding="utf-8"))[:limit]
    model = _model_label()
    slug = re.sub(r"[^A-Za-z0-9.-]+", "-", model)
    run_dir = Path(results_dir) / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}_{system}_{slug}"
    run_dir.mkdir(parents=True, exist_ok=True)

    runner = SYSTEMS[system]
    rows: list[dict] = []
    with open(run_dir / "predictions.jsonl", "w", encoding="utf-8") as f:
        for i, alert in enumerate(alerts, 1):
            start = time.perf_counter()
            error = None
            try:
                predicted = runner(alert)
            except Exception as e:
                predicted, error = [], f"{type(e).__name__}: {e}"
            latency = time.perf_counter() - start

            row = {
                "alert_id":  alert["alert_id"],
                "expected":  alert["expected_techniques"],
                "predicted": normalize_ids(predicted),
                "latency_s": round(latency, 2),
                "error":     error,
                **score_prediction(predicted, alert["expected_techniques"]),
            }
            rows.append(row)
            f.write(json.dumps(row) + "\n")
            f.flush()
            status = f"ERROR {error}" if error else ("HIT" if row["exact"]["recall"] else "miss")
            print(f"[{i}/{len(alerts)}] {alert['alert_id']} expected={row['expected']} "
                  f"predicted={row['predicted']} {latency:.1f}s {status}", flush=True)

    summary = summarize(rows, system=system, model=model, dataset=Path(dataset_path).name)
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\n" + format_table([summary]))
    print(f"\nResults written to {run_dir}")
    return run_dir


def load_summaries(results_dir: Path = RESULTS_DIR) -> list[dict]:
    return [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(Path(results_dir).glob("*/summary.json"))
    ]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="ATT&CK technique-mapping benchmark.")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="Build the labeled dataset from MITRE ATT&CK.")
    build.add_argument("--source", default=ATTCK_URL, help="URL or local path of enterprise-attack.json")
    build.add_argument("--n", type=int, default=50, help="Number of examples (one per technique)")
    build.add_argument("--seed", type=int, default=42)
    build.add_argument("--out", type=Path, default=DEFAULT_DATASET)

    run = sub.add_parser("run", help="Run one system over the dataset.")
    run.add_argument("--system", choices=sorted(SYSTEMS), required=True)
    run.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    run.add_argument("--limit", type=int, default=None, help="Only the first N examples (smoke test)")

    sub.add_parser("report", help="Print a table of every completed run.")

    args = parser.parse_args()

    if args.command == "build":
        dataset = build_dataset(_load_bundle(args.source), n=args.n, seed=args.seed)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(dataset, indent=2), encoding="utf-8")
        print(f"Wrote {len(dataset)} examples to {args.out}")
    elif args.command == "run":
        run_benchmark(args.system, args.dataset, args.limit)
    else:
        summaries = load_summaries()
        print(format_table(summaries) if summaries else "No results yet -- run a benchmark first.")


if __name__ == "__main__":
    main()
