"""
eval/ablation.py

Per-role model ablation harness (Foundation-sec-8B-Reasoning vs
Llama 3.3-70B vs GLM-4.5-Air per agent role).

This does NOT change config/models.yaml. For a fixed evaluation set of
alert fixtures (see data/alerts/), it re-runs a single agent role with each
candidate model from `ablation_candidates` in models.yaml, holding every
other agent's model fixed, and collects the raw outputs for later scoring
(triage accuracy, ATT&CK technique F1, calibration error, latency, cost --
see the benchmarking protocol in docs/report.pdf).

This is intentionally a thin harness: it only orchestrates "run role X with
candidate model Y against fixture set Z"; metric computation lives in
separate eval modules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from config import load_yaml


@dataclass
class AblationRun:
    agent_role: str
    candidate_model: str
    fixture_id: str
    output: Dict[str, Any] = field(default_factory=dict)
    latency_seconds: float = 0.0
    tool_calls_used: int = 0


def load_ablation_candidates() -> List[str]:
    return load_yaml("models.yaml").get("ablation_candidates", [])


def run_role_ablation(
    agent_role: str,
    agent_fn: Callable[[dict, str], dict],
    fixtures: List[dict],
    candidates: Optional[List[str]] = None,
) -> List[AblationRun]:
    """
    agent_fn: a callable (state, model_id) -> state, i.e. one of the
    agents/*.py entry points adapted to accept an explicit model override
    instead of reading config/models.yaml internally.
    fixtures: list of SOCInvestigationState dicts to run the ablation over.
    """
    if candidates is None:
        candidates = load_ablation_candidates()

    runs: List[AblationRun] = []
    for candidate in candidates:
        for fixture in fixtures:
            output_state = agent_fn(dict(fixture), candidate)
            runs.append(
                AblationRun(
                    agent_role=agent_role,
                    candidate_model=candidate,
                    fixture_id=fixture.get("alert_id", "unknown"),
                    output=output_state,
                )
            )
    return runs
