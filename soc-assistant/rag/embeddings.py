"""
rag/embeddings.py

Embedding backend shared by the Chroma-backed stores (store_attck.py,
store_cti_reports.py).

Set SOC_ASSISTANT_MOCK_EMBEDDINGS=1 to force a zero-dependency fake
embedder instead of downloading a real HuggingFace sentence-transformer
model -- useful for tests/CI and offline demos, where exact embedding
quality doesn't matter.
"""
from __future__ import annotations

import os

_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
_EMBEDDING_DIM = 384


class SimpleFakeEmbeddings:
    """Zero-dependency stand-in embedder: fixed-length zero vectors.

    Similarity search over this embedder is meaningless (every vector is
    identical) -- it exists purely so the pipeline can run end to end
    without downloading a real model.
    """

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [[0.0] * _EMBEDDING_DIM for _ in texts]

    def embed_query(self, text: str) -> list[float]:
        return [0.0] * _EMBEDDING_DIM


def build_embedder():
    """Return the configured embedder, degrading to SimpleFakeEmbeddings
    if the real model or its package is unavailable."""
    if os.environ.get("SOC_ASSISTANT_MOCK_EMBEDDINGS") == "1":
        return SimpleFakeEmbeddings()
    try:
        from langchain_huggingface import HuggingFaceEmbeddings
        return HuggingFaceEmbeddings(model_name=_EMBEDDING_MODEL)
    except Exception:
        return SimpleFakeEmbeddings()


def get_chroma_class():
    """Return the Chroma vector-store class, preferring langchain-chroma."""
    try:
        from langchain_chroma import Chroma
    except ImportError:
        from langchain_community.vectorstores import Chroma
    return Chroma
