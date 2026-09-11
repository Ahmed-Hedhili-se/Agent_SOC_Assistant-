"""
rag/store_attck.py

Store 1 - MITRE ATT&CK (hybrid vector + BM25 in the full design; Chroma
similarity search for this prototype).

The embedder and the Chroma collection are NOT created at import time.
`import rag.store_attck` must be cheap and side-effect-free (no network
calls, no model download) so that unrelated modules can import this
package without paying that cost. The store is built lazily on the first
call to get_attck_store() and cached afterwards.
"""
from __future__ import annotations

from pathlib import Path

from rag.embeddings import build_embedder, get_chroma_class

_PERSIST_DIR = Path(__file__).parent / "db" / "attck"
_attck_store = None  # lazy singleton, populated by get_attck_store()


def get_attck_store():
    """Return the (lazily-initialized, cached) ATT&CK Chroma collection."""
    global _attck_store
    if _attck_store is None:
        Chroma = get_chroma_class()
        _attck_store = Chroma(
            collection_name="mitre_attck",
            embedding_function=build_embedder(),
            persist_directory=str(_PERSIST_DIR),
        )
    return _attck_store
