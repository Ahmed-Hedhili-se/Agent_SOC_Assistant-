"""
tests/test_llm_parsing.py

Tests for agents/_llm.py: recovering an agent's JSON answer from the
varied shapes real models return it in.
"""
from __future__ import annotations

from agents._llm import parse_json_response, strip_reasoning


def test_plain_json():
    assert parse_json_response('{"severity": 9.0}') == {"severity": 9.0}


def test_json_with_surrounding_prose():
    assert parse_json_response('Here you go:\n{"verdict": "actionable"}\nHope that helps.') == {
        "verdict": "actionable"
    }


def test_markdown_fenced_json():
    assert parse_json_response('```json\n{"technique_ids": ["T1059.001"]}\n```') == {
        "technique_ids": ["T1059.001"]
    }


def test_reasoning_block_is_stripped():
    content = (
        "<think>Maybe {\"technique_ids\": [\"T1055\"]}? No, that's process injection.</think>\n"
        '{"technique_ids": ["T1059.001"]}'
    )
    assert parse_json_response(content) == {"technique_ids": ["T1059.001"]}


def test_unclosed_reasoning_block_yields_no_answer():
    assert parse_json_response('<think>still thinking {"a": 1}') == {}


def test_last_json_object_wins_over_earlier_drafts():
    content = '{"technique_ids": []}\nOn reflection:\n{"technique_ids": ["T1105"]}'
    assert parse_json_response(content) == {"technique_ids": ["T1105"]}


def test_nested_objects_are_preserved():
    assert parse_json_response('{"entities": {"ips": ["10.0.0.1"]}}') == {
        "entities": {"ips": ["10.0.0.1"]}
    }


def test_garbage_returns_empty_dict():
    assert parse_json_response("no json here at all") == {}
    assert parse_json_response("") == {}
    assert parse_json_response("{not: valid json}") == {}


def test_strip_reasoning_keeps_plain_text():
    assert strip_reasoning("just text") == "just text"
