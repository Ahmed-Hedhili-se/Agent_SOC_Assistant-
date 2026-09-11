"""
review/feedback/rag_update.py

Analyst feedback loop -- records corrections and updates the RAG knowledge base.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

_FEEDBACK_LOG_PATH = Path(__file__).resolve().parents[2] / "data" / "feedback_log.jsonl"


def update_rag_from_correction(correction: dict) -> None:
    """
    On analyst modify/reject:
      1. Appends the correction to a persistent feedback ledger (JSONL).
      2. (In production) Would re-embed the corrected verdict into the
         relevant Chroma store for online learning.

    Args:
        correction: dict with keys:
            - investigation_id
            - action (modify | reject)
            - corrected_fields  (list of dotted field paths)
            - analyst_note
            - original_verdict
            - timestamp
    """
    entry = {
        **correction,
        "logged_at": datetime.now(timezone.utc).isoformat(),
    }

    _FEEDBACK_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_FEEDBACK_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    print(
        f"[FEEDBACK] Correction logged for investigation "
        f"{correction.get('investigation_id')} | action={correction.get('action')} "
        f"| fields={correction.get('corrected_fields')}"
    )
