"""
eval/override_rate.py

Per-agent override rate: how often analysts correct each agent's output
via the HITL decision endpoint.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable

from review.feedback.preference_pairs import ROLE_OUTPUT_KEYS


def calculate_override_rate_by_role(decisions: Iterable[dict]) -> Dict[str, float]:
    """
    Compute override rate attributed per upstream agent role.

    Each element of `decisions` is expected to look like:
        {
            "action": "approve" | "modify" | "reject" | "escalate",
            "corrected_fields": ["triage_output.severity", "attck_output.technique_ids", ...],
        }

    `corrected_fields` entries are dotted paths whose first segment is the
    state slot written by a given agent (e.g. "triage_output" -> "triage";
    see ROLE_OUTPUT_KEYS).

    Returns a dict of {agent_role: override_rate}, where override_rate is the
    fraction of decisions touching that role's output that were "modify" or
    "reject" (an "approve" or "escalate" with no corrected field for that
    role does not count against it).
    """
    touched = defaultdict(int)
    overridden = defaultdict(int)

    for decision in decisions:
        action = decision.get("action")
        roles_in_this_decision = {
            ROLE_OUTPUT_KEYS[prefix]
            for field in decision.get("corrected_fields", [])
            if (prefix := field.split(".")[0]) in ROLE_OUTPUT_KEYS
        }

        for role in roles_in_this_decision:
            touched[role] += 1
            if action in ("modify", "reject"):
                overridden[role] += 1

    return {role: overridden[role] / touched[role] for role in touched}
