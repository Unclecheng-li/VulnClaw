"""🦞 VulnClaw — AI-powered penetration testing CLI tool."""

from pathlib import Path
from importlib.metadata import PackageNotFoundError, version

try:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    version_line = next(
        line for line in pyproject.read_text(encoding="utf-8").splitlines()
        if line.startswith("version = ")
    )
    __version__ = version_line.split('"')[1]
except Exception:
    try:
        __version__ = version("vulnclaw")
    except PackageNotFoundError:
        __version__ = "0.2.6"

__author__ = "VulnClaw Team"
