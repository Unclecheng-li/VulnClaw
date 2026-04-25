"""VulnClaw Agent Runtime State — per-run mutable state containers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AgentResult:
    """Result from a single agent turn."""

    output: str = ""
    target: Optional[str] = None
    phase: Optional[str] = None
    tool_calls: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    should_continue: bool = True  # Whether the agent should keep looping


@dataclass
class PersistentCycleResult:
    """Result from a single persistent pentest cycle."""

    cycle_num: int = 0
    results: list = field(default_factory=list)  # list[AgentResult]
    report_path: Optional[str] = None
    total_findings: int = 0
    total_steps: int = 0
    new_findings: int = 0
    stopped_early: bool = False  # User interrupted or hard limit reached


@dataclass
class RuntimeState:
    """Per-run mutable state for autonomous/persistent loops."""

    auto_skill_input: str = ""
    user_vuln_hint: str = ""
    user_vuln_hint_rounds: int = 0

    claimed_flag: Optional[str] = None
    flag_verified: bool = False
    flag_claim_count: int = 0
    post_flag_rounds: int = 0

    is_recon_phase: bool = False
    rounds_without_progress: int = 0
    last_findings_count: int = 0
    last_notes_count: int = 0
    last_steps_count: int = 0
    python_timeout_rounds: int = 0

    seen_step_signatures: set[str] = field(default_factory=set)
    current_attack_path: Optional[str] = None
    same_path_fail_count: int = 0
    path_switch_forced: bool = False

    failed_targets: dict[str, int] = field(default_factory=dict)
    blocked_targets: set[str] = field(default_factory=set)

    unverified_assumptions: list[str] = field(default_factory=list)
    is_ctf_mode: bool = False
    consecutive_errors: int = 0
