"""🦞 VulnClaw — AI-powered penetration testing CLI tool."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("vulnclaw")
except PackageNotFoundError:
    __version__ = "0.2.5"

__author__ = "VulnClaw Team"
