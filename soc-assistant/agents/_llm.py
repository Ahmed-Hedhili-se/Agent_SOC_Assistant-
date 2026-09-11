"""
agents/_llm.py

Helpers shared by every agent node for talking to the configured LLM.
"""
from __future__ import annotations

import json
import re


def parse_json_response(content: str) -> dict:
    """Extract and parse the first JSON object from an LLM response string.

    Returns an empty dict if no valid JSON object can be recovered, so
    callers can fall back to their own defaults via `parsed.get(...)`.
    """
    try:
        return json.loads(content.strip())
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
    return {}
