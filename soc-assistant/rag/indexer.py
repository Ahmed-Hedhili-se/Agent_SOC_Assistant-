"""
rag/indexer.py

Downloads and indexes MITRE ATT&CK enterprise techniques into Store 1.

A failed download degrades to a no-op with a clear message rather than
raising -- a knowledge-base seeding step should never take down the
pipeline.

Usage (from soc-assistant/):
    python -m rag.indexer
"""
from __future__ import annotations

import requests

from rag.store_attck import get_attck_store

_ATTCK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def index_attck(timeout_seconds: int = 30) -> int:
    """Download and index MITRE ATT&CK enterprise techniques.

    Returns the number of techniques indexed (0 on failure).
    """
    try:
        response = requests.get(_ATTCK_URL, timeout=timeout_seconds)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[indexer] Could not fetch ATT&CK data ({type(e).__name__}: {e}); skipping index.")
        return 0

    documents = []
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            technique_id = obj.get("external_references", [{}])[0].get("external_id", "")
            doc = f"""
            Technique: {technique_id} -- {obj.get('name')}
            Tactic: {', '.join(p.get('phase_name', '') for p in obj.get('kill_chain_phases', []))}
            Description: {obj.get('description', '')}
            Detection: {obj.get('x_mitre_detection', '')}
            """
            documents.append({"content": doc, "metadata": {"technique_id": technique_id}})

    if not documents:
        print("[indexer] No attack-pattern objects found in the downloaded data; nothing to index.")
        return 0

    attck_store = get_attck_store()
    attck_store.add_texts(
        [d["content"] for d in documents],
        metadatas=[d["metadata"] for d in documents],
    )
    print(f"[indexer] Indexed {len(documents)} ATT&CK techniques.")
    return len(documents)


if __name__ == "__main__":
    index_attck()
