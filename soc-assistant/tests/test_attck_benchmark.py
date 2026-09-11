"""
tests/test_attck_benchmark.py

Tests for eval/attck_benchmark.py: dataset construction (no answer
leakage), scoring, and an end-to-end mock run.
"""
from __future__ import annotations

import json

from eval import attck_benchmark as bench


def _technique(stix_id, tid, name, **extra):
    return {"type": "attack-pattern", "id": stix_id, "name": name,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}], **extra}


def _uses(rel_id, source, target, description, **extra):
    return {"type": "relationship", "relationship_type": "uses", "id": rel_id,
            "source_ref": source, "target_ref": target, "description": description, **extra}


BUNDLE = {"objects": [
    {"type": "intrusion-set", "id": "intrusion-set--apt"},
    _technique("attack-pattern--ps", "T1059.001", "PowerShell"),
    _technique("attack-pattern--old", "T9999", "Old", revoked=True),
    _uses("relationship--1", "intrusion-set--apt", "attack-pattern--ps",
          "[APT](https://attack.mitre.org/groups/G0001) has used encoded [PowerShell](https://attack.mitre.org/techniques/T1059/001) "
          "commands (T1059.001) to download payloads.(Citation: Report 2020)"),
    _uses("relationship--2", "intrusion-set--apt", "attack-pattern--ps",
          "A second procedure example for the very same technique, long enough to qualify."),
    _uses("relationship--3", "intrusion-set--apt", "attack-pattern--old",
          "This procedure targets a revoked technique and must be skipped entirely."),
]}


def test_clean_description_strips_citations_links_and_ids():
    text = bench.clean_description(
        "[APT](https://x/G1) used [PowerShell](https://x/T1059/001) (T1059.001).(Citation: R)"
    )
    assert "Citation" not in text
    assert "https://" not in text
    assert "T1059" not in text
    assert "APT used PowerShell" in text


def test_build_dataset_one_example_per_active_technique():
    dataset = bench.build_dataset(BUNDLE, n=10)
    assert len(dataset) == 1
    alert = dataset[0]
    assert alert["expected_techniques"] == ["T1059.001"]
    assert "T1059" not in alert["raw_log"]


def test_build_dataset_is_reproducible():
    assert bench.build_dataset(BUNDLE, seed=7) == bench.build_dataset(BUNDLE, seed=7)


def test_public_alert_hides_ground_truth():
    alert = bench.build_dataset(BUNDLE)[0]
    public = bench._public_alert(alert)
    assert not (set(public) & bench._GROUND_TRUTH_KEYS)


def test_score_prediction_exact_vs_parent():
    score = bench.score_prediction(["t1059.003", "T1105"], ["T1059.001"])
    assert score["n_predicted"] == 2
    assert score["exact"]["recall"] == 0.0
    assert score["parent"]["recall"] == 1.0
    assert score["parent"]["precision"] == 0.5


def test_score_prediction_empty_prediction():
    score = bench.score_prediction([], ["T1059.001"])
    assert score["exact"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def test_mcnemar_exact_p():
    assert bench.mcnemar_exact_p(0, 0) == 1.0
    assert bench.mcnemar_exact_p(5, 5) == 1.0
    assert round(bench.mcnemar_exact_p(18, 4), 4) == 0.0043


def test_compare_systems_pairs_latest_runs(tmp_path):
    def write_run(name, system, hits):
        run = tmp_path / name
        run.mkdir()
        (run / "summary.json").write_text(json.dumps({"system": system, "model": "m"}), encoding="utf-8")
        rows = [{"alert_id": f"A{i}", "exact": {"recall": float(h)}, "parent": {"recall": 1.0}}
                for i, h in enumerate(hits)]
        (run / "predictions.jsonl").write_text("\n".join(map(json.dumps, rows)), encoding="utf-8")

    write_run("1_baseline_m", "baseline", [1, 0, 0, 0])
    write_run("1_mapper_m", "mapper", [1, 1, 1, 0])

    exact, parent = bench.compare_systems("baseline", "mapper", "m", results_dir=tmp_path)
    assert (exact["only_mapper"], exact["only_baseline"], exact["n"]) == (2, 0, 4)
    assert parent["p_value"] == 1.0


def test_run_benchmark_mock_writes_predictions_and_summary(tmp_path):
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps(bench.build_dataset(BUNDLE)), encoding="utf-8")

    run_dir = bench.run_benchmark("mapper", dataset_path, results_dir=tmp_path / "results")

    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["n"] == 1
    assert summary["model"] == "mock"
    assert summary["errors"] == 0
    assert len((run_dir / "predictions.jsonl").read_text(encoding="utf-8").splitlines()) == 1
    assert "| mapper | mock | 1 |" in bench.format_table(bench.load_summaries(tmp_path / "results"))
