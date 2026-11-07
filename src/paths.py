"""Where things live. Everything is resolved from the project root (the folder that contains src/), never from the current directory,
so the scripts behave the same wherever they are started from. Environment variables override the defaults:

    SECUREIT_OUTPUT_DIR   where run folders are written and read   (default: <root>/runs)
    SECUREIT_COMPANIES    the companies file                        (default: <root>/config/companies.json)
    SECUREIT_ENV_FILE     the file with the app client ids/secrets  (default: <root>/.env)
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
DATA_DIR = ROOT / "data"
SPECS_DIR = ROOT / "specs"


def output_dir() -> Path:
    return Path(os.environ.get("SECUREIT_OUTPUT_DIR") or ROOT / "runs")


def companies_file() -> Path:
    return Path(os.environ.get("SECUREIT_COMPANIES") or CONFIG_DIR / "companies.json")


def env_file() -> Path:
    return Path(os.environ.get("SECUREIT_ENV_FILE") or ROOT / ".env")
