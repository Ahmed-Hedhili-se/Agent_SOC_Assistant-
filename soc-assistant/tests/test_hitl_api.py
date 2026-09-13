"""
tests/test_hitl_api.py

Tests for the dashboard-facing parts of hitl/api.py: the queue summary
endpoint, decision state in the evidence view, and the served UI.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import hitl.api as hitl_api
    import review.feedback.preference_pairs as pp
    import review.feedback.rag_update as ru

    monkeypatch.setattr(hitl_api, "_STORE_PATH", tmp_path / "active_investigations.json")
    monkeypatch.setattr(pp, "_PAIRS_DIR", tmp_path / "dpo_pairs")
    monkeypatch.setattr(ru, "_FEEDBACK_LOG_PATH", tmp_path / "feedback_log.jsonl")
    hitl_api._decision_log.clear()

    hitl_api.register_investigation("ALT-1", {
        "alert_id": "ALT-1",
        "alert_timestamp": "2026-07-27T08:00:00Z",
        "alert_raw": {"category": "impossible_travel", "source": "Identity"},
        "triage_output": {"severity": 7.5, "category": "impossible_travel"},
        "synthesis_output": {"verdict": "actionable", "confidence": 0.85},
        "confidence_score": 0.85,
        "escalation_flag": True,
        "agents_completed": ["triage", "cti_enrichment"],
        "agents_failed": ["attck_mapper"],
    })
    return TestClient(hitl_api.app)


def test_summaries_endpoint_returns_queue_fields(client):
    rows = client.get("/investigations/summaries").json()
    assert rows == [{
        "alert_id": "ALT-1",
        "category": "impossible_travel",
        "source": "Identity",
        "timestamp": "2026-07-27T08:00:00Z",
        "severity": 7.5,
        "verdict": "actionable",
        "confidence": 0.85,
        "escalation_flag": True,
        "hitl_decision": None,
        "approved_by": None,
        "sla_deadline": "2026-07-27T09:00:00+00:00",
    }]


def test_summaries_route_is_not_shadowed_by_investigation_id(client):
    assert client.get("/investigations/summaries").status_code == 200
    assert client.get("/investigations/ALT-1").status_code == 200


def test_evidence_exposes_decision_state_after_approval(client):
    before = client.get("/investigations/ALT-1").json()
    assert before["hitl_decision"] is None
    assert before["agents_failed"] == ["attck_mapper"]

    client.post("/investigations/ALT-1/decision",
                json={"action": "approve", "analyst_id": "jane", "note": "confirmed"})

    after = client.get("/investigations/ALT-1").json()
    assert after["hitl_decision"] == "approve"
    assert after["approved_by"] == "jane"
    summary = client.get("/investigations/summaries").json()[0]
    assert summary["approved_by"] == "jane"


def test_dashboard_is_served(client):
    page = client.get("/ui/")
    assert page.status_code == 200
    assert "Analyst Console" in page.text
    assert client.get("/", follow_redirects=False).headers["location"] == "/ui/"
