"""
agents/_llm.py

Helpers shared by every agent node for talking to the configured LLM.
"""
from __future__ import annotations

import json
import re

# Reasoning models (Foundation-Sec-8B-Reasoning, qwen3, ...) wrap their
# chain of thought in tags and only then emit the answer. The thought text
# routinely contains braces and draft JSON, so it is stripped before any
# JSON is extracted.
_THINK_BLOCK_RE = re.compile(
    r"<(think|thinking|reasoning)>.*?</\1>|<(think|thinking|reasoning)>.*",
    re.DOTALL | re.IGNORECASE,
)


def strip_reasoning(content: str) -> str:
    """Remove <think>-style reasoning blocks, including an unclosed trailing one."""
    return _THINK_BLOCK_RE.sub("", content or "").strip()


def _json_objects(text: str):
    """Yield every balanced {...} substring, outermost first."""
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0:
                yield text[start:i + 1]


def parse_json_response(content: str) -> dict:
    """Extract and parse the agent's JSON answer from an LLM response.

    Tolerates reasoning blocks, prose around the JSON, and markdown fences.
    When several JSON objects are present the LAST one wins: models that
    narrate tend to emit drafts before the final answer. Returns an empty
    dict if nothing parses, so callers fall back to their own defaults via
    `parsed.get(...)`.
    """
    text = strip_reasoning(content)
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    best: dict = {}
    for candidate in _json_objects(text):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and parsed:
            best = parsed
    return best
