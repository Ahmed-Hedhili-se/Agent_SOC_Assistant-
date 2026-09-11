"""
rag/store_cti_reports.py

Store 2 - CTI reports (Mandiant, CrowdStrike, Unit42, CISA). Hybrid
retrieval filtered by techniques_mentioned in the full design; Chroma
similarity search for this prototype.

Same lazy-init contract as rag/store_attck.py.
"""
from __future__ import annotations

from pathlib import Path

from rag.embeddings import build_embedder, get_chroma_class

_PERSIST_DIR = Path(__file__).parent / "db" / "cti"
_cti_store = None  # lazy singleton, populated by get_cti_store()


def get_cti_store():
    """Return the (lazily-initialized, cached) CTI reports Chroma collection."""
    global _cti_store
    if _cti_store is None:
        Chroma = get_chroma_class()
        _cti_store = Chroma(
            collection_name="cti_reports",
            embedding_function=build_embedder(),
            persist_directory=str(_PERSIST_DIR),
        )
    return _cti_store
