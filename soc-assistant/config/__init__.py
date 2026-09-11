"""
config

YAML configuration files plus helpers to load them by name. Paths are
resolved from this package's location, so loading works regardless of the
caller's current working directory.
"""
from __future__ import annotations

from pathlib import Path

import yaml

CONFIG_DIR = Path(__file__).resolve().parent


def load_yaml(name: str) -> dict:
    """Load `config/<name>` (e.g. "thresholds.yaml") as a dict."""
    with open(CONFIG_DIR / name, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
