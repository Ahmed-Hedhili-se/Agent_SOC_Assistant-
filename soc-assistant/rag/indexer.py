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

# Pinned release (April 2024) rather than master: technique IDs get
# renumbered over time, and a release predating the LLMs' training cutoff
# keeps retrieval, model knowledge and eval/attck_benchmark.py consistent.
ATTCK_VERSION = "v15.1"
ATTCK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/"
    f"ATT%26CK-{ATTCK_VERSION}/enterprise-attack/enterprise-attack.json"
)


def index_attck(timeout_seconds: int = 120) -> int:
    """Download and index MITRE ATT&CK enterprise techniques.

    Returns the number of techniques indexed (0 on failure).
    """
    try:
        response = requests.get(ATTCK_URL, timeout=timeout_seconds)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[indexer] Could not fetch ATT&CK data ({type(e).__name__}: {e}); skipping index.")
        return 0

    documents = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id = next(
            (ref.get("external_id") for ref in obj.get("external_references", [])
             if ref.get("source_name") == "mitre-attack"),
            "",
        )
        doc = f"""
        Technique: {technique_id} -- {obj.get('name')}
        Tactic: {', '.join(p.get('phase_name', '') for p in obj.get('kill_chain_phases', []))}
        Description: {obj.get('description', '')}
        Detection: {obj.get('x_mitre_detection', '')}
        """
        documents.append({"id": obj["id"], "content": doc, "metadata": {"technique_id": technique_id}})

    if not documents:
        print("[indexer] No attack-pattern objects found in the downloaded data; nothing to index.")
        return 0

    # Keyed by STIX id, so re-running the indexer upserts instead of duplicating.
    attck_store = get_attck_store()
    attck_store.add_texts(
        [d["content"] for d in documents],
        metadatas=[d["metadata"] for d in documents],
        ids=[d["id"] for d in documents],
    )
    print(f"[indexer] Indexed {len(documents)} ATT&CK techniques.")
    return len(documents)


if __name__ == "__main__":
    index_attck()
