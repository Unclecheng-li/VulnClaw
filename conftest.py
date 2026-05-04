from __future__ import annotations

import os
import tempfile
from uuid import uuid4
from pathlib import Path

import pytest


TEST_ROOT = Path(__file__).resolve().parent / ".test-tmp"
TEST_ROOT.mkdir(parents=True, exist_ok=True)
os.environ["VULNCLAW_CONFIG_DIR"] = str(TEST_ROOT / "config")
os.environ["TMPDIR"] = str(TEST_ROOT)
os.environ["TEMP"] = str(TEST_ROOT)
os.environ["TMP"] = str(TEST_ROOT)
tempfile.tempdir = str(TEST_ROOT)


@pytest.fixture
def tmp_path() -> Path:
    """Project-local writable tmp_path replacement for this workspace."""
    path = TEST_ROOT / f"tmp-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    return path
