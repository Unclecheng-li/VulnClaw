"""VulnClaw session context management — track pentest state across turns."""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


class PentestPhase(str, Enum):
    """Penetration test phases."""

    IDLE = "就绪"
    RECON = "信息收集"
    VULN_DISCOVERY = "漏洞发现"
    EXPLOITATION = "漏洞利用"
    POST_EXPLOITATION = "后渗透"
    REPORTING = "报告生成"


class VulnerabilityFinding(BaseModel):
    """A single vulnerability finding."""

    title: str = Field(description="Vulnerability title")
    severity: str = Field(default="Medium", description="Critical/High/Medium/Low/Info")
    vuln_type: str = Field(default="", description="Vulnerability type (SQLi, XSS, RCE, etc.)")
    description: str = Field(default="", description="Detailed description")
    evidence: str = Field(default="", description="Proof/evidence of the finding")
    cve: Optional[str] = Field(default=None, description="Associated CVE ID")
    remediation: str = Field(default="", description="Fix recommendation")
    poc_script: Optional[str] = Field(default=None, description="Generated PoC script path")


class SessionState(BaseModel):
    """Full session state for a pentest engagement."""

    target: Optional[str] = None
    phase: PentestPhase = PentestPhase.IDLE
    started_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    recon_data: dict[str, Any] = Field(default_factory=dict)
    executed_steps: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    def add_finding(self, finding: VulnerabilityFinding) -> None:
        """Add a vulnerability finding."""
        self.findings.append(finding)

    def add_step(self, step: str) -> None:
        """Record an executed step."""
        self.executed_steps.append(step)

    def add_note(self, note: str) -> None:
        """Add a session note."""
        self.notes.append(note)

    def advance_phase(self, phase: PentestPhase) -> None:
        """Move to a new phase."""
        self.phase = phase
        self.add_step(f"阶段切换 → {phase.value}")

    def save(self, path: Optional[Path] = None) -> Path:
        """Save session state to JSON file."""
        if path is None:
            from vulnclaw.config.settings import SESSIONS_DIR
            safe_target = (self.target or "unknown").replace("/", "_").replace(":", "_")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = SESSIONS_DIR / f"{timestamp}_{safe_target}.json"

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(mode="json"), f, ensure_ascii=False, indent=2)
        return path

    @classmethod
    def load(cls, path: Path) -> "SessionState":
        """Load session state from JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)


class ContextManager:
    """Manages conversation context and session state."""

    def __init__(self, max_history: int = 50) -> None:
        self.max_history = max_history
        self.messages: list[dict[str, str]] = []
        self.state = SessionState()

    def add_user_message(self, content: str) -> None:
        """Add a user message to context."""
        self.messages.append({"role": "user", "content": content})
        self._trim()

    def add_assistant_message(self, content: str) -> None:
        """Add an assistant message to context."""
        self.messages.append({"role": "assistant", "content": content})
        self._trim()

    def add_system_message(self, content: str) -> None:
        """Add a system message (inserted at beginning)."""
        # System messages are handled separately in the API call
        pass

    def get_messages(self) -> list[dict[str, str]]:
        """Get conversation messages for API call."""
        return self.messages.copy()

    def reset(self) -> None:
        """Reset context and session state."""
        self.messages = []
        self.state = SessionState()

    def _trim(self) -> None:
        """Trim old messages to stay within limit."""
        if len(self.messages) > self.max_history:
            # Keep the most recent messages
            self.messages = self.messages[-self.max_history:]

    def trim_messages(self, max_messages: int = 20) -> None:
        """Forcefully trim conversation history to a specific size.

        Used when context overflow causes repeated LLM errors.
        """
        if len(self.messages) > max_messages:
            self.messages = self.messages[-max_messages:]
