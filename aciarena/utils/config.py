"""Configuration loading with environment overrides for reproducible local runs."""

from __future__ import annotations

import os
from pathlib import Path

import yaml


def load_llm_config(path: str | Path, prefix: str = "ACI_ARENA") -> dict:
    with Path(path).open("r", encoding="utf-8") as stream:
        config = yaml.safe_load(stream)

    overrides = {
        "provider": os.getenv(f"{prefix}_PROVIDER"),
        "api_key": os.getenv(f"{prefix}_API_KEY"),
        "base_url": os.getenv(f"{prefix}_BASE_URL"),
        "model_name": os.getenv(f"{prefix}_MODEL_NAME"),
        "temperature": os.getenv(f"{prefix}_TEMPERATURE"),
        "max_tokens": os.getenv(f"{prefix}_MAX_TOKENS"),
    }
    for key, value in overrides.items():
        if value is not None:
            config[key] = value

    if "temperature" in config:
        config["temperature"] = float(config["temperature"])
    if "max_tokens" in config:
        config["max_tokens"] = int(config["max_tokens"])
    return config
