"""
Shared pytest setup: puts soc-assistant/ on sys.path and runs every test
offline -- mock embeddings (no model download) and deterministic mock LLM
completions (no Ollama/vLLM server; see config/provider.py).
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

os.environ["SOC_ASSISTANT_MOCK_EMBEDDINGS"] = "1"
os.environ["SOC_ASSISTANT_MOCK_LLM"] = "1"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
