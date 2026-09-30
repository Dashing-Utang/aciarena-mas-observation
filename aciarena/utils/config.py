"""Configuration loading with environment-variable expansion."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml


ENV_VALUE = re.compile(r"^\$\{([A-Z_][A-Z0-9_]*)\}$")


def load_llm_config(path: str | Path) -> dict:
    """Load YAML and resolve values written as ``${ENVIRONMENT_VARIABLE}``."""

    with Path(path).open("r", encoding="utf-8") as stream:
        config = yaml.safe_load(stream)

    for key, value in config.items():
        if not isinstance(value, str):
            continue
        match = ENV_VALUE.fullmatch(value)
        if not match:
            continue
        variable = match.group(1)
        resolved = os.getenv(variable)
        if not resolved:
            raise ValueError(
                f"Environment variable {variable} is required by {path}."
            )
        config[key] = resolved

    return config
