"""VulnClaw Agent Core — the main AI agent loop with tool calling."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.agent.context import ContextManager, PentestPhase, SessionState
from vulnclaw.agent.prompts import build_system_prompt, AUTO_PENTEST_INSTRUCTION, RECON_INSTRUCTION

# ── Recon minimum rounds & dimension tracking ──────────────────────

RECON_MIN_ROUNDS = 8  # 信息收集阶段最低轮数，低于此数 [DONE] 被忽略

# Keywords that indicate each recon dimension has been explored
# ⚠️ These keywords must ONLY appear in tool results (not LLM reasoning text)
# Personnel dimension uses tool-result-only detection to avoid code snippet false positives
_RECON_DIM_KEYWORDS: dict[str, list[str]] = {
    "server": [
        "端口", "port", "nmap", "开放", "open", "服务版本", "service",
        "真实ip", "real ip", "cdn", "源站", "操作系统", "os检测", "ttl",
        "中间件", "middleware", "数据库", "database", "mysql", "redis",
    ],
    "website": [
        "waf", "web应用防火墙", "敏感目录", "目录扫描", "dirsearch", "gobuster",
        "源码泄露", ".git", ".svn", ".ds_store", ".env", "备份文件", ".bak",
        "旁站", "同ip", "c段", "同网段", "指纹", "cms", "框架", "framework",
        "架构", "技术栈", "web指纹",
    ],
    "domain": [
        "whois", "注册人", "注册商", "icp", "备案", "子域名", "subdomain",
        "dns记录", "cname", "mx记录", "txt记录", "证书透明", "crt.sh",
        "证书信息", "ssl证书",
    ],
    # ⚠️ personnel: 只检测真正的社工行动结果，不靠代码片段中的通用词
    # "github", "邮箱", "twitter" 等在任何 python_execute 代码中都可能出现
    "personnel": [
        # 真正的 GitHub API 返回结果特征
        "github_id", "followers", "following", "public_repos",
        "unclecheng",  # 从 GitHub API 返回中提取的真实姓名
        # 真正的社工发现结果（不是代码中的字符串）
        "twitter",  # 但必须是 URL 路径中的，不是 import 语句
    ],
}


# ── Think tag filtering ────────────────────────────────────────

# Closed think blocks: <think>...</think> or <thinking>...</thinking>
_THINK_CLOSED = re.compile(
    r"<(?:think|thinking)>.*?</(?:think|thinking)>",
    re.DOTALL | re.IGNORECASE,
)

# Unclosed think blocks: <thinking>... (no closing tag, extends to end of text)
# This is common with DeepSeek R1 and other reasoning models that output
# <thinking> without a matching </thinking>
_THINK_UNCLOSED = re.compile(
    r"<(?:think|thinking)>.*",
    re.DOTALL | re.IGNORECASE,
)

# Opening/closing tag patterns for extracting inner content
_OPEN_TAG = re.compile(r"^<(?:think|thinking)>", re.IGNORECASE)
_CLOSE_TAG = re.compile(r"</(?:think|thinking)>$", re.IGNORECASE)


def strip_think_tags(text: str) -> str:
    """Remove all <think>/<thinking> blocks from text.
    
    Handles both closed and unclosed think tags.
    Many reasoning models (DeepSeek R1, etc.) output <thinking> without
    a closing </thinking> tag, causing the rest of the content to be
    swallowed as part of the thinking block.
    """
    # First pass: remove closed blocks
    text = _THINK_CLOSED.sub("", text)
    # Second pass: remove unclosed blocks (tag with no closing, eats rest of text)
    text = _THINK_UNCLOSED.sub("", text)
    return text.strip()


def format_think_tags(text: str, show: bool) -> str:
    """Format output based on show_thinking setting.

    If show=True:  keep think tags and content as-is (untouched).
    If show=False: strip think tags and their content entirely.
    
    Handles both closed and unclosed think tags.
    """
    if show:
        # Return the text as-is — thinking tags and content are preserved
        return text
    return strip_think_tags(text)

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


class AgentCore:
    """Core AI agent that orchestrates LLM calls and tool execution."""

    def __init__(self, config: VulnClawConfig, mcp_manager: Any = None) -> None:
        self.config = config
        self.mcp_manager = mcp_manager
        self.context = ContextManager()
        self._client = None

    @property
    def session_state(self) -> SessionState:
        """Access current session state."""
        return self.context.state

    def reset_context(self) -> None:
        """Reset agent context."""
        self.context.reset()

    def _get_client(self):
        """Lazy-initialize OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    api_key=self.config.llm.api_key,
                    base_url=self.config.llm.base_url,
                )
            except ImportError:
                raise RuntimeError("请安装 openai 包: pip install openai")
        return self._client

    def _build_system_prompt(self, target: Optional[str] = None, auto_mode: bool = False, user_input: Optional[str] = None) -> str:
        """Build the dynamic system prompt for this turn."""
        # Collect MCP tools if available
        mcp_tools = []
        if self.mcp_manager:
            mcp_tools = self.mcp_manager.get_tool_schemas()

        # Collect skill context — dynamically dispatch based on user input
        skill_context = self._get_active_skill_context(user_input=user_input)

        # Determine current phase
        phase = self.context.state.phase.value if self.context.state.phase != PentestPhase.IDLE else None

        # ★ Determine if personnel dimension (dimension 4) should be enabled
        # Only enable when user explicitly mentions social engineering / OSINT / author tracking
        personnel_keywords = [
            "社会工程", "社工", "人员信息", "作者追踪", "人物追踪", "人物画像",
            "osint", "情报", "调查", "作者",
        ]
        enable_personnel = any(kw in (user_input or "").lower() for kw in personnel_keywords)
        # Also check recon_dimension4_active from state (set during auto_pentest init)
        if hasattr(self.context.state, 'recon_dimension4_active') and self.context.state.recon_dimension4_active:
            enable_personnel = True

        prompt = build_system_prompt(
            target=target or self.context.state.target,
            phase=phase,
            skill_context=skill_context,
            mcp_tools=mcp_tools,
            enable_personnel_dim=enable_personnel,
        )

        # Add auto-pentest instruction when in autonomous mode
        if auto_mode:
            prompt += "\n\n" + AUTO_PENTEST_INSTRUCTION

        # Add recon instruction when user input suggests information gathering
        if user_input:
            recon_triggers = [
                "搜集", "收集", "信息收集", "侦察", "recon", "osint",
                "社会工程", "社工", "调查", "作者", "人物", "情报",
                "分析目标", "目标分析", "资产发现", "子域名",
            ]
            if any(t in user_input.lower() for t in recon_triggers):
                if enable_personnel:
                    # Full four-dimension model including personnel
                    prompt += "\n\n" + RECON_INSTRUCTION
                else:
                    # Three-dimension model — personnel dimension deactivated
                    # Mark dimension 4 items as skipped so LLM knows not to do social eng
                    recon_no_personnel = RECON_INSTRUCTION.replace(
                        "### 维度四：人员信息 ⚡ 条件触发",
                        "### 维度四：人员信息 ⚡ 条件触发（本次未激活 — 用户未提及社工/人员追踪需求）"
                    )
                    # Replace unchecked items with "skipped" marks
                    recon_no_personnel = recon_no_personnel.replace(
                        "- [ ] 姓名 & 职务",
                        "- [x] 姓名 & 职务（未激活，跳过）"
                    ).replace(
                        "- [ ] 生日 & 联系电话",
                        "- [x] 生日 & 联系电话（未激活，跳过）"
                    ).replace(
                        "- [ ] 邮件地址",
                        "- [x] 邮件地址（未激活，跳过）"
                    ).replace(
                        "- [ ] 社交媒体账号（B站、微博、知乎、Twitter、LinkedIn、GitHub）",
                        "- [x] 社交媒体账号（未激活，跳过）"
                    ).replace(
                        "- [ ] 跨平台关联（用用户名/邮箱搜索其他平台，检查历史提交记录中的邮箱）",
                        "- [x] 跨平台关联（未激活，跳过）"
                    )
                    prompt += "\n\n" + recon_no_personnel

        return prompt

    def _get_active_skill_context(self, user_input: Optional[str] = None) -> Optional[str]:
        """Get context from the most relevant Skill based on user input.

        Uses the SkillDispatcher to dynamically select the best Skill
        for the current task. Falls back to pentest-flow if no input
        or no match is found.
        """
        if user_input:
            try:
                from vulnclaw.skills.dispatcher import SkillDispatcher
                dispatcher = SkillDispatcher()
                skill = dispatcher.dispatch(user_input)
                if skill:
                    context = skill.get("content", "")
                    # If the skill has references, append a summary of available refs
                    refs = skill.get("references", [])
                    if refs:
                        ref_list = ", ".join(refs[:10])
                        if len(refs) > 10:
                            ref_list += f", ... ({len(refs)} total)"
                        context += f"\n\n## 可用参考文档\n以下参考文档可在需要时通过 load_skill_reference 加载: {ref_list}"
                    return context
            except Exception:
                pass

        # Fallback to pentest-flow for general / no-input scenarios
        try:
            from vulnclaw.skills.loader import load_skill_by_name
            skill = load_skill_by_name("pentest-flow")
            if skill:
                return skill.get("content", "")
        except Exception:
            pass
        return None

    def _detect_phase(self, user_input: str) -> Optional[PentestPhase]:
        """Detect pentest phase from user input using keyword matching."""
        input_lower = user_input.lower()

        phase_keywords = {
            PentestPhase.RECON: [
                "信息收集", "侦察", "端口扫描", "子域名", "指纹", "目录扫描",
                "recon", "scan", "端口", "nmap", "收集",
            ],
            PentestPhase.VULN_DISCOVERY: [
                "漏洞发现", "漏洞扫描", "有什么漏洞", "cve", "安全检测",
                "vulnerability", "漏洞", "注入", "xss", "sqli",
            ],
            PentestPhase.EXPLOITATION: [
                "利用", "exploit", "poc", "验证漏洞", "执行命令", "rce",
                "getshell", "拿权限", "打一下", "尝试",
            ],
            PentestPhase.POST_EXPLOITATION: [
                "后渗透", "内网", "横向", "提权", "维持", "pivot",
                "post-exploitation", "隧道", "代理",
            ],
            PentestPhase.REPORTING: [
                "报告", "report", "总结", "整理", "生成报告",
            ],
        }

        for phase, keywords in phase_keywords.items():
            if any(kw in input_lower for kw in keywords):
                return phase

        # Default to recon if target is mentioned
        target_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP
            r'https?://\S+',  # URL
        ]
        for pattern in target_patterns:
            if re.search(pattern, user_input):
                return PentestPhase.RECON

        return None

    def _detect_target(self, user_input: str) -> Optional[str]:
        """Extract target from user input."""
        # Try to find URL (with optional port)
        url_match = re.search(r'(https?://[a-zA-Z0-9][-a-zA-Z0-9.:]*)', user_input)
        if url_match:
            return url_match.group(1).rstrip("/")
        # Try to find IP address
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', user_input)
        if ip_match:
            return ip_match.group(1)

        # Try to find domain
        domain_match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', user_input)
        if domain_match:
            return domain_match.group(1)

        return None

    # ── Single-turn chat (for manual REPL interaction) ──────────────

    async def chat(self, user_input: str, target: Optional[str] = None) -> AgentResult:
        """Process a user message and return agent response (single turn).

        For multi-step tasks with targets, use auto_pentest() instead.
        Chat mode is for quick Q&A and simple single-step queries.
        """
        result = AgentResult()

        # Detect target and phase from input
        detected_target = target or self._detect_target(user_input)
        detected_phase = self._detect_phase(user_input)

        # Update session state
        if detected_target:
            self.context.state.target = detected_target
            result.target = detected_target

        if detected_phase:
            self.context.state.advance_phase(detected_phase)
            result.phase = detected_phase.value

        # Add user message to context
        self.context.add_user_message(user_input)

        # Build system prompt — pass user_input for dynamic Skill dispatch
        system_prompt = self._build_system_prompt(detected_target, auto_mode=False, user_input=user_input)

        # Call LLM
        try:
            response_text = await self._call_llm(system_prompt)
            result.output = response_text

            # Add assistant response to context
            self.context.add_assistant_message(response_text)

            # Parse any structured findings from the response
            self._parse_findings(response_text)

            # Auto-save session
            self.context.state.save()

        except Exception as e:
            result.output = f"[!] Agent 错误: {e}"

        return result

    # ── Autonomous pentest loop ─────────────────────────────────────

    async def auto_pentest(
        self,
        user_input: str,
        target: Optional[str] = None,
        max_rounds: int = 15,
        on_step: Optional[Callable[[int, AgentResult], None]] = None,
    ) -> list[AgentResult]:
        """Autonomous penetration test loop.

        Given a target and intent, the agent will continuously:
        1. Analyze current state
        2. Decide next action (use tool / advance phase / report)
        3. Execute the action
        4. Evaluate results
        5. Repeat until done or max_rounds reached

        This mirrors the KFC AI / Codex agentic loop pattern.

        Args:
            user_input: The user's initial request (e.g. "对 xxx 进行渗透测试")
            target: Optional explicit target override
            max_rounds: Maximum number of autonomous rounds (default 15)
            on_step: Callback invoked after each round with (round_num, result)

        Returns:
            List of AgentResult from each round.
        """
        results: list[AgentResult] = []

        # ── Round 0: Initial setup ──────────────────────────────────
        detected_target = target or self._detect_target(user_input)
        detected_phase = self._detect_phase(user_input) or PentestPhase.RECON

        if detected_target:
            self.context.state.target = detected_target
        if detected_phase:
            self.context.state.advance_phase(detected_phase)

        # Add user's initial request to context
        self.context.add_user_message(user_input)

        # ── Skill dispatch: determine the best Skill for this task ──
        # We dispatch once based on the initial input and reuse it for all rounds
        self._auto_skill_input = user_input

        # Reset flag verification state for this run
        self._claimed_flag = None
        self._flag_verified = False
        self._flag_claim_count = 0  # Track how many times the same flag is claimed
        self._post_flag_rounds = 0  # Track rounds after flag is verified (safety exit)

        # ★ Recon dimension completion tracking
        self._is_recon_phase = detected_phase == PentestPhase.RECON
        if self._is_recon_phase:
            self.context.state.recon_dimensions_completed = {
                "server": False, "website": False, "domain": False, "personnel": False,
            }
            # Detect if dimension 4 (personnel) should be activated
            social_engineering_keywords = [
                "社会工程", "社工", "人员信息", "作者追踪", "人物追踪", "人物画像",
                "osint", "情报", "作者", "调查",
            ]
            self.context.state.recon_dimension4_active = any(
                kw in user_input.lower() for kw in social_engineering_keywords
            )

        # ★ Dead-loop detection: track rounds without progress
        self._rounds_without_progress = 0
        self._last_findings_count = 0
        self._last_notes_count = 0
        self._last_steps_count = 0

        # ★ Attack path tracking: detect when the agent is stuck on one path
        self._current_attack_path = None  # e.g. "regex_bypass", "rce", "file_inclusion"
        self._same_path_fail_count = 0
        self._path_switch_forced = False

        # ★ Assumption tracking: help the LLM verify its assumptions
        self._unverified_assumptions = []  # assumptions noted by the agent

        # ★ Detect CTF mode — when user explicitly asks for flag/CTF,
        # we enforce strict termination: must have verified flag to stop
        ctf_keywords = ["ctf", "flag", "夺旗", "解题", "找flag", "找出flag"]
        self._is_ctf_mode = any(kw in user_input.lower() for kw in ctf_keywords)

        # ── Autonomous loop ─────────────────────────────────────────
        for round_num in range(1, max_rounds + 1):
            result = AgentResult()
            result.target = self.context.state.target
            result.phase = self.context.state.phase.value

            # Build system prompt with auto-mode instruction
            # Reuse the Skill dispatched from the initial input
            system_prompt = self._build_system_prompt(
                self.context.state.target,
                auto_mode=True,
                user_input=getattr(self, '_auto_skill_input', user_input),
            )

            # Add a round marker to the conversation so the LLM knows it's in a loop
            round_context = self._build_round_context(round_num, max_rounds)

            try:
                # Call LLM with full conversation + round context
                # Note: _call_llm_auto persists tool call results to context internally
                # so we don't add the response again for the tool call path
                response_text = await self._call_llm_auto(system_prompt, round_context)
                result.output = response_text

                # Add the LLM's final text response to context
                # (tool call summaries are already added inside _call_llm_auto)
                self.context.add_assistant_message(f"[Round {round_num} 分析] {response_text}")

                # Parse findings
                self._parse_findings(response_text)

                # ★ Auto-detect recon dimension completion from LLM output
                if getattr(self, '_is_recon_phase', False):
                    self._update_recon_dimension_completion(response_text)

                # ★ Check if the LLM performed a verification step
                # If notes contain "验证成功" or similar, mark flag as verified
                if hasattr(self, '_claimed_flag') and self._claimed_flag and not getattr(self, '_flag_verified', False):
                    verification_markers = [
                        # 显式验证表达
                        "验证成功", "验证通过", "已验证", "复现成功", "确认flag",
                        "verified", "confirmed", "flag正确", "提交成功",
                        # LLM 实际常用的表达方式
                        "flag 获取成功", "flag获取成功", "获取成功", "找到flag",
                        "flag found", "成功获取", "获取了flag", "拿到了flag",
                        "成功拿到", "成功找到", "解题完成", "解题成功",
                    ]
                    if any(m in response_text.lower() for m in verification_markers):
                        self._flag_verified = True

                # ★ CTF mode: also auto-verify if the claimed flag appears in tool results
                # This handles cases where the LLM extracts the flag from a tool response
                # but doesn't explicitly say "验证成功"
                if getattr(self, '_is_ctf_mode', False) and self._claimed_flag and not getattr(self, '_flag_verified', False):
                    # Method 1: Check if the flag appears in notes (from real tool output)
                    flag_in_notes_count = sum(
                        1 for note in self.context.state.notes
                        if self._claimed_flag in note
                    )
                    # If flag appears in notes ≥ 2 times from different tool calls,
                    # it's been independently confirmed
                    if flag_in_notes_count >= 2:
                        self._flag_verified = True
                    elif flag_in_notes_count >= 1:
                        # Flag appears once in notes — check if LLM also claimed it
                        # (which means both tool output and LLM analysis agree)
                        if self._claimed_flag in response_text:
                            self._flag_verified = True

                # Detect phase transitions from LLM output
                new_phase = self._detect_phase_from_output(response_text)
                if new_phase and new_phase != self.context.state.phase:
                    self.context.state.advance_phase(new_phase)
                    result.phase = new_phase.value

                # Check if agent signals completion
                result.should_continue = not self._is_completion_signal(response_text)

                # ★ Flag verification tracking — detect flag claims in LLM output
                claimed_flag = self._detect_flag_claim(response_text)
                if claimed_flag:
                    if not hasattr(self, '_claimed_flag') or not self._claimed_flag:
                        # First time flag is claimed — record it, force one verification round
                        self._claimed_flag = claimed_flag
                        self._flag_verified = False
                        result.should_continue = True
                    elif self._claimed_flag == claimed_flag and not getattr(self, '_flag_verified', False):
                        # Same flag claimed again but not yet verified — keep going
                        # BUT: add a safety cap — if this is the 3rd+ time the same
                        # unverified flag appears, auto-verify to avoid infinite loop
                        if not hasattr(self, '_flag_claim_count'):
                            self._flag_claim_count = 0
                        self._flag_claim_count += 1
                        if self._flag_claim_count >= 3:
                            # Same flag claimed 3+ times — likely genuine, auto-verify
                            self._flag_verified = True
                        else:
                            result.should_continue = True

                # ★ CTF mode: block [DONE] if no verified flag
                # In CTF, the only valid completion is getting and verifying the flag.
                # LLM might say [DONE] prematurely (e.g. "found the file with the flag"
                # but never actually extracted the flag value).
                if getattr(self, '_is_ctf_mode', False) and not result.should_continue:
                    flag_verified = getattr(self, '_flag_verified', False)
                    claimed_flag = getattr(self, '_claimed_flag', None)
                    if not flag_verified or not claimed_flag:
                        # Block termination — force continue
                        result.should_continue = True

                # ★ Recon phase: block [DONE] if minimum rounds not met or dimensions incomplete
                # Prevents the LLM from prematurely concluding info gathering
                if getattr(self, '_is_recon_phase', False) and not result.should_continue:
                    # Check 1: Minimum rounds not yet reached
                    if round_num < RECON_MIN_ROUNDS:
                        result.should_continue = True
                    # Check 2: Not all active dimensions have been explored
                    elif not self.context.state.is_recon_complete():
                        result.should_continue = True
                    # ★ IMPORTANT: if flag IS verified and LLM says [DONE], LET IT STOP
                    # This is the key fix — previously _flag_verified never became True,
                    # so the agent kept looping even after successful flag verification

                # ★ Post-flag safety exit: if flag is verified, allow [DONE] to stop the loop
                # Also: if the LLM keeps repeating the same verified flag + [DONE],
                # force-stop after 2 rounds to avoid the "celebration loop" problem
                if getattr(self, '_flag_verified', False) and getattr(self, '_claimed_flag', None):
                    if not hasattr(self, '_post_flag_rounds'):
                        self._post_flag_rounds = 0
                    self._post_flag_rounds += 1
                    # After flag is verified, allow at most 2 more rounds for summary,
                    # then force-stop regardless
                    if self._post_flag_rounds >= 2:
                        result.should_continue = False

                # Record step
                self.context.state.add_step(f"Round {round_num}: {response_text[:100]}...")

                # ★ Dead-loop detection: check if we're making progress
                current_findings = len(self.context.state.findings)
                current_notes = len(self.context.state.notes)
                current_steps = len(self.context.state.executed_steps)
                
                has_new_progress = (
                    current_findings > self._last_findings_count
                    or current_notes > self._last_notes_count
                    or current_steps > self._last_steps_count + 1  # +1 because we just added a step
                )
                
                if has_new_progress:
                    self._rounds_without_progress = 0
                else:
                    self._rounds_without_progress += 1
                
                self._last_findings_count = current_findings
                self._last_notes_count = current_notes
                self._last_steps_count = current_steps

                # ★ Attack path tracking: detect if we're stuck on the same approach
                # by checking the LLM output for repeated keywords/techniques
                if not has_new_progress and not getattr(self, '_path_switch_forced', False):
                    # Extract the attack technique from this round's output
                    detected_path = self._detect_attack_path(response_text)
                    if detected_path:
                        if detected_path == getattr(self, '_current_attack_path', None):
                            self._same_path_fail_count += 1
                        else:
                            # New path — reset counter
                            self._current_attack_path = detected_path
                            self._same_path_fail_count = 0
                            self._path_switch_forced = False
                elif has_new_progress:
                    # Progress made — reset path tracking
                    self._same_path_fail_count = 0
                    self._path_switch_forced = False

                # Auto-save
                self.context.state.save()

            except Exception as e:
                result.output = f"[!] Round {round_num} 错误: {e}"
                # Don't kill the loop on recoverable errors — allow up to 2 consecutive failures
                if not hasattr(self, '_consecutive_errors'):
                    self._consecutive_errors = 0
                self._consecutive_errors += 1
                if self._consecutive_errors >= 3:
                    result.should_continue = False
                else:
                    result.should_continue = True
                    # Trim conversation to avoid context overflow causing repeated failures
                    self.context.trim_messages(max_messages=20)
            else:
                # Reset error counter on success
                if hasattr(self, '_consecutive_errors'):
                    self._consecutive_errors = 0

            results.append(result)

            # Notify via callback
            if on_step:
                on_step(round_num, result)

            # Stop if agent says it's done
            if not result.should_continue:
                break

        return results

    def _build_round_context(self, round_num: int, max_rounds: int) -> str:
        """Build context string for the current round in auto loop."""
        state = self.context.state
        findings_summary = ""
        if state.findings:
            findings_summary = f"\n已发现漏洞: {len(state.findings)} 个"
            for f in state.findings[-5:]:  # Show last 5 findings
                findings_summary += f"\n  - [{f.severity}] {f.title}: {f.evidence[:100]}"

        steps_summary = ""
        if state.executed_steps:
            # Show recent steps in more detail
            recent_steps = state.executed_steps[-8:]
            steps_summary = f"\n最近执行步骤: {len(state.executed_steps)} 个总计"
            for s in recent_steps:
                steps_summary += f"\n  - {s[:150]}"

        # ★ Failed attempts tracking — critical for CTF to avoid repeating mistakes
        failed_summary = ""
        if state.executed_steps:
            failed_attempts = []
            failure_markers = [
                "失败", "没有", "返回相同", "被拦截", "404", "no",
                "未成功", "无效", "error", "failed", "still",
                "未发现", "无结果", "timeout", "禁止", "denied",
                "不存在", "无法", "不能", "不对",
            ]
            for step in state.executed_steps:
                if any(marker in step.lower() for marker in failure_markers):
                    failed_attempts.append(step[:150])
            if failed_attempts:
                failed_summary = f"\n失败历史（不要重复这些操作）:"
                for f in failed_attempts[-10:]:  # Keep last 10 failures
                    failed_summary += f"\n  ❌ {f}"

        recon_summary = ""
        if state.recon_data:
            recon_summary = f"\n侦察数据: {list(state.recon_data.keys())}"

        # Include notes (important for CTF hints)
        notes_summary = ""
        if state.notes:
            notes_summary = f"\n重要笔记: {'; '.join(state.notes[-5:])}"

        # ★ Confirmed facts vs unverified assumptions — critical for reasoning quality
        facts_summary = ""
        if hasattr(state, 'confirmed_facts') and state.confirmed_facts:
            facts_summary = f"\n已确认事实（工具验证过，可信）:"
            for fact in state.confirmed_facts[-8:]:
                facts_summary += f"\n  ✅ {fact[:150]}"

        assumptions_summary = ""
        if hasattr(state, 'unverified_assumptions') and state.unverified_assumptions:
            assumptions_summary = f"\n⚠️ 未验证假设（推理基础但未确认，可能错误）:"
            for assumption in state.unverified_assumptions[-5:]:
                assumptions_summary += f"\n  ❓ {assumption[:150]}"
            assumptions_summary += "\n→ 如果某条假设是错的，基于它的推理全部作废！优先验证关键假设。"

        # ★ Path switch warning — if stuck on same approach for too long
        path_warning = ""
        same_path_fails = getattr(self, '_same_path_fail_count', 0)
        if state.executed_steps:
            recent = state.executed_steps[-8:]
            if len(recent) >= 5:
                # Check if recent steps all mention the same parameter/technique
                # Simple heuristic: if the last 5 steps share common substrings
                recent_text = " ".join(recent).lower()
                stuck_indicators = ["get=", "post=", "payload", "参数", "尝试"]
                stuck_count = sum(1 for ind in stuck_indicators if recent_text.count(ind) >= 3)
                if stuck_count >= 1:
                    path_warning = (
                        "\n\n⚠️ 你已经在当前路径上尝试了多轮但没有突破。"
                        "\n请重新审视源码/信息，是否有其他更简单的利用路径？"
                        "\n列出所有可能的路径，然后切换到最简单的一条。"
                    )

        # ★ Attack path stuck warning — if same path fails 3+ times, force path switch
        path_switch_warning = ""
        if same_path_fails >= 3:
            path_switch_warning = (
                f"\n\n🔴 路径切换强制指令：你已经在同一条攻击路径上失败了 {same_path_fails} 次！"
                f"\n你必须立即执行以下步骤："
                f"\n1. 停下来，列出至少 3 条**完全不同**的替代攻击路径"
                f"\n   （不是换 payload 值，而是换攻击方式：如从'绕过正则'换成'伪协议读文件'或'数组绕过'）"
                f"\n2. 按难度从低到高排序这些替代路径"
                f"\n3. 选择最简单的替代路径开始尝试"
                f"\n4. 在尝试新路径前，先花 1 轮验证你的新假设"
                f"\n\n⚠️ 禁止继续在同一路径上换 payload 值尝试！"
            )
            # Reset the counter to avoid repeating the warning forever
            self._same_path_fail_count = 0
            self._path_switch_forced = True

        # ★ Assumption verification reminder — remind LLM to verify assumptions
        assumption_reminder = ""
        if round_num > 2 and round_num % 3 == 0:
            assumption_reminder = (
                "\n\n🧠 假设验证检查点："
                "\n在做下一步之前，花 10 秒问自己："
                "\n1. 我当前的推理基于什么假设？"
                "\n2. 这些假设我验证过了吗？还是只是在想当然？"
                "\n3. 如果某个假设是错的，我的整个推理链会崩塌吗？"
                "\n4. 我能花 1 轮发送一个请求来验证最关键的假设吗？"
                "\n\n❌ 常见致命假设：preg_replace 只替换第一个匹配 / Python 模拟 = 服务器行为 / 参数名是某个值"
            )

        # ★ Dead-loop detection — if no progress for multiple rounds
        dead_loop_warning = ""
        rounds_no_progress = getattr(self, '_rounds_without_progress', 0)
        stale_threshold = self.config.session.stale_rounds_threshold
        if rounds_no_progress >= stale_threshold:
            dead_loop_warning = (
                f"\n\n🔴 严重警告：你已经连续 {rounds_no_progress} 轮没有任何新发现！"
                f"\n这表明你陷入了死循环。你必须立即采取以下措施之一："
                f"\n1. 🔥 重新获取完整源码（用 python_execute + strip_tags）"
                f"\n2. 🔥 尝试完全不同的攻击路径（换参数名、换方法、换工具）"
                f"\n3. 🔥 如果当前信息不足，承认并尝试其他信息收集方法"
                f"\n4. 🔥 停止重复相同操作！回顾失败历史，选择新方向"
                f"\n\n⚠️ 再次重复相同操作将不会产生不同结果！"
            )
        elif rounds_no_progress >= max(stale_threshold // 2, 2):
            dead_loop_warning = (
                f"\n\n⚠️ 警告：你已经连续 {rounds_no_progress} 轮没有新发现。"
                f"\n请检查：是否在重复相同操作？是否有其他未尝试的路径？"
                f"\n如果当前方法不work，立即切换到其他方法。"
            )

        # Flag verification warning — if a flag was claimed but not verified
        flag_warning = ""
        claimed_flag = getattr(self, '_claimed_flag', None)
        flag_verified = getattr(self, '_flag_verified', False)
        post_flag_rounds = getattr(self, '_post_flag_rounds', 0)
        if claimed_flag and flag_verified:
            # Flag is verified — tell the LLM to wrap up
            flag_warning = (
                f"\n\n✅ FLAG 已验证: {claimed_flag}"
                f"\n你的任务已完成！请简洁总结解题过程，然后标记 [DONE] 结束。"
                f"\n⚠️ 不要重复验证或重复发送请求！立即总结并结束。"
            )
        elif claimed_flag and not flag_verified:
            flag_warning = (
                f"\n\n⚠️ 你之前声称找到了 flag: {claimed_flag}"
                f"\n但这个 flag 未经独立验证！你必须："
                f"\n1. 用工具重新发送 payload 确认结果可复现"
                f"\n2. 或用不同方法交叉验证（如换一个函数/路径读取同一内容）"
                f"\n3. 如果验证失败，必须承认之前的 flag 是错误的，继续解题"
                f"\n在验证完成前，不要标记 [DONE]"
            )

        # ★ CTF mode: enforce no early termination without flag
        ctf_mode_warning = ""
        is_ctf = getattr(self, '_is_ctf_mode', False)
        if is_ctf and not claimed_flag:
            ctf_mode_warning = (
                f"\n\n🔴 CTF 解题模式 — 你的任务是找到 flag 并验证。"
                f"\n当前你还没有找到任何 flag，禁止标记 [DONE]。"
                f"\n请分析已有信息，选择最有可能的攻击路径继续推进。"
                f"\n如果当前路径受阻，尝试切换到其他路径。"
            )
        elif is_ctf and claimed_flag and not flag_verified:
            ctf_mode_warning = (
                f"\n\n🔴 CTF 解题模式 — 你声称找到了 flag 但未验证。"
                f"\n必须用工具验证 flag 的真实性后才能标记 [DONE]。"
                f"\n如果验证失败，必须继续寻找正确的 flag。"
            )
        elif is_ctf and claimed_flag and flag_verified:
            # Flag verified — no need for CTF warning, flag_warning already handles it
            pass

        # ★ Recon dimension completion status — prevent premature [DONE]
        recon_dim_status = ""
        if getattr(self, '_is_recon_phase', False):
            dim_status_text = self.context.state.get_recon_status_text()
            is_complete = self.context.state.is_recon_complete()
            rounds_no_progress = getattr(self, '_rounds_without_progress', 0)
            recon_dim_status = (
                f"\n\n📊 信息收集维度完成度:"
                f"\n{dim_status_text}"
            )
            if not is_complete:
                recon_dim_status += (
                    f"\n\n🔴 信息收集未完成！还有维度未检查，禁止标记 [DONE]。"
                    f"\n请继续对未完成的维度执行检查，确保每个维度都至少做过一轮。"
                )
            elif is_complete and rounds_no_progress >= 3:
                # ★ Force summary: all dims done + no new progress for 3+ rounds
                recon_dim_status += (
                    f"\n\n🔴 侦察强制总结指令："
                    f"\n你已经连续 {rounds_no_progress} 轮没有任何新的工具发现，所有维度均已完成 ✅。"
                    f"\n请立即执行以下操作（不要继续发送请求）："
                    f"\n1. 整理已收集的所有侦察信息"
                    f"\n2. 使用 python_execute 将侦察报告保存到桌面"
                    f"\n   路径格式: ~/Desktop/{{目标}}_侦察报告_{{日期}}.md"
                    f"\n3. 在回复末尾添加 [DONE] 标记结束本次侦察"
                    f"\n⚠️ 禁止继续重复分析已有信息或发送新请求！"
                )
            if round_num < RECON_MIN_ROUNDS:
                recon_dim_status += (
                    f"\n\n🔴 信息收集最低轮数保障：当前第 {round_num} 轮，"
                    f"最低需 {RECON_MIN_ROUNDS} 轮。即使觉得够了也请继续深入。"
                )

        return (
            f"\n\n[自主循环 Round {round_num}/{max_rounds}]"
            f"\n当前目标: {state.target or '未设置'}"
            f"\n当前阶段: {state.phase.value}"
            f"{findings_summary}"
            f"{facts_summary}"
            f"{assumptions_summary}"
            f"{steps_summary}"
            f"{failed_summary}"
            f"{recon_summary}"
            f"{notes_summary}"
            f"{path_warning}"
            f"{path_switch_warning}"
            f"{assumption_reminder}"
            f"{dead_loop_warning}"
            f"{flag_warning}"
            f"{ctf_mode_warning}"
            f"{recon_dim_status}"
            f"\n\n请基于当前状态和之前所有发现决定下一步操作，持续推进渗透测试。"
            f"\n注意：不要重复之前已经做过的操作，专注于推进到下一步。"
            f"\n如果发现重要线索或完成测试，在回复末尾添加 [DONE] 标记。"
        )

    # ── Persistent pentest loop ──────────────────────────────────────

    async def persistent_pentest(
        self,
        user_input: str,
        target: Optional[str] = None,
        rounds_per_cycle: int = 100,
        max_cycles: int = 10,
        auto_report: bool = True,
        on_cycle_step: Optional[Callable[[int, int, AgentResult], None]] = None,
        on_cycle_complete: Optional[Callable[[int, "PersistentCycleResult"], None]] = None,
    ) -> list["PersistentCycleResult"]:
        """Persistent penetration test — runs cycles of auto_pentest until stopped.

        Each cycle runs up to `rounds_per_cycle` rounds. After each cycle:
        - A cycle report is auto-generated (if auto_report=True)
        - The session state is preserved across cycles for continuity
        - The next cycle continues from where the previous left off

        The loop continues until:
        - max_cycles is reached (default 10, set 0 for unlimited)
        - User interrupts via Ctrl+C
        - The agent signals completion with [DONE] and no new findings

        Args:
            user_input: The user's initial request (e.g. "对 xxx 进行持续性渗透测试")
            target: Optional explicit target override
            rounds_per_cycle: Number of rounds per cycle (default 100)
            max_cycles: Maximum number of cycles (default 10, 0=unlimited)
            auto_report: Auto-generate report after each cycle
            on_cycle_step: Callback(round_num, cycle_num, result) for each step
            on_cycle_complete: Callback(cycle_num, cycle_result) after each cycle

        Returns:
            List of PersistentCycleResult for each completed cycle.
        """
        cycle_results: list[PersistentCycleResult] = []

        # ── Cycle 0: Initial setup ──────────────────────────────────
        detected_target = target or self._detect_target(user_input)
        if detected_target:
            self.context.state.target = detected_target

        # Add user's initial request to context
        self.context.add_user_message(user_input)

        # Store initial skill dispatch
        self._auto_skill_input = user_input

        # Reset flag verification state for this run
        self._claimed_flag = None
        self._flag_verified = False
        self._flag_claim_count = 0
        self._post_flag_rounds = 0

        # ★ Dead-loop detection for persistent mode too
        self._rounds_without_progress = 0
        self._last_findings_count = 0
        self._last_notes_count = 0
        self._last_steps_count = 0

        # ★ Attack path tracking for persistent mode
        self._current_attack_path = None
        self._same_path_fail_count = 0
        self._path_switch_forced = False

        # ★ Detect CTF mode for persistent pentest too
        ctf_keywords = ["ctf", "flag", "夺旗", "解题", "找flag", "找出flag"]
        self._is_ctf_mode = any(kw in user_input.lower() for kw in ctf_keywords)

        # Track cumulative findings across cycles for delta detection
        findings_at_cycle_start = len(self.context.state.findings)

        # ── Persistent cycle loop ─────────────────────────────────────
        cycle_num = 0
        should_stop = False

        while not should_stop:
            cycle_num += 1

            # Check hard limit
            if max_cycles > 0 and cycle_num > max_cycles:
                should_stop = True
                break

            # Run one cycle of auto_pentest
            cycle_results_list: list[AgentResult] = []

            def _make_step_callback(cycle: int):
                """Create a step callback that captures cycle number."""
                def _on_step(round_num: int, result: AgentResult) -> None:
                    cycle_results_list.append(result)
                    if on_cycle_step:
                        on_cycle_step(round_num, cycle, result)
                return _on_step

            try:
                results = await self.auto_pentest(
                    user_input=(
                        f"[Persistent Cycle {cycle_num}] 继续对目标 {self.context.state.target or '未知'} "
                        f"进行渗透测试。这是第 {cycle_num} 个周期，保持之前的所有发现继续深入。"
                        if cycle_num > 1 else user_input
                    ),
                    target=self.context.state.target,
                    max_rounds=rounds_per_cycle,
                    on_step=_make_step_callback(cycle_num),
                )
                cycle_results_list = results if results else cycle_results_list
            except KeyboardInterrupt:
                # User interrupted during the cycle
                should_stop = True
                cycle_results_list = cycle_results_list or []

            # Compute cycle stats
            total_findings = len(self.context.state.findings)
            total_steps = len(self.context.state.executed_steps)
            new_findings = total_findings - findings_at_cycle_start
            findings_at_cycle_start = total_findings

            # Generate cycle report
            report_path = None
            if auto_report:
                try:
                    from vulnclaw.report.generator import generate_persistent_cycle_report
                    report_path = generate_persistent_cycle_report(
                        session=self.context.state,
                        cycle_num=cycle_num,
                        total_findings=total_findings,
                        new_findings=new_findings,
                        total_steps=total_steps,
                        rounds_per_cycle=rounds_per_cycle,
                    )
                except Exception as e:
                    report_path = f"报告生成失败: {e}"

            # Build cycle result
            cycle_result = PersistentCycleResult(
                cycle_num=cycle_num,
                results=cycle_results_list,
                report_path=str(report_path) if report_path else None,
                total_findings=total_findings,
                total_steps=total_steps,
                stopped_early=should_stop,
            )
            cycle_results.append(cycle_result)

            # Notify via callback
            if on_cycle_complete:
                on_cycle_complete(cycle_num, cycle_result)

            # Check if the agent signaled completion in the last cycle
            if cycle_results_list and not should_stop:
                last_result = cycle_results_list[-1]
                if not last_result.should_continue:
                    # Agent said it's done — but in persistent mode, we continue
                    # unless there are truly no new findings
                    if new_findings == 0 and total_findings > 0:
                        # No new findings and agent says done — meaningful completion
                        should_stop = True

        return cycle_results

    def _detect_phase_from_output(self, output: str) -> Optional[PentestPhase]:
        """Detect phase transition signals from LLM output."""
        output_lower = output.lower()

        # Phase transition signals
        transitions = [
            (PentestPhase.VULN_DISCOVERY, ["进入漏洞发现", "开始漏洞扫描", "漏洞检测", "切换到漏洞发现", "phase: vuln_discovery"]),
            (PentestPhase.EXPLOITATION, ["进入漏洞利用", "开始利用", "尝试利用", "切换到漏洞利用", "phase: exploitation"]),
            (PentestPhase.POST_EXPLOITATION, ["进入后渗透", "内网渗透", "横向移动", "切换到后渗透", "phase: post_exploitation"]),
            (PentestPhase.REPORTING, ["生成报告", "整理结果", "渗透测试完成", "切换到报告", "phase: reporting"]),
        ]

        for phase, signals in transitions:
            if any(s in output_lower for s in signals):
                return phase

        return None

    def _is_completion_signal(self, output: str) -> bool:
        """Check if the LLM output signals task completion."""
        completion_signals = [
            "[DONE]",
            "[COMPLETE]",
            "渗透测试已完成",
            "测试结束",
            "任务完成",
        ]
        return any(s in output for s in completion_signals)

    def _detect_flag_claim(self, output: str) -> Optional[str]:
        """Detect if the LLM claims to have found a flag, return the claimed flag or None.

        This is used to trigger automatic verification — if the LLM claims
        a flag but we can't verify it independently, we should NOT stop.
        """
        # Common CTF flag patterns
        flag_patterns = [
            r'(NSSCTF\{[^}]+\})',
            r'(CTF\{[^}]+\})',
            r'(flag\{[^}]+\})',
            r'(Flag\{[^}]+\})',
            r'(FLAG\{[^}]+\})',
        ]
        for pattern in flag_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _detect_attack_path(self, output: str) -> Optional[str]:
        """Detect the current attack path/technique from LLM output.

        Returns a canonical path name like "regex_bypass", "rce", "file_inclusion", etc.
        Used to track whether the agent is stuck on the same approach.
        """
        output_lower = output.lower()

        # Attack path patterns — ordered by specificity (more specific first)
        path_patterns = [
            ("regex_bypass", ["preg_replace", "preg_match", "正则绕过", "大小写绕过", "数组绕过", "双写绕过"]),
            ("file_inclusion", ["php://filter", "文件包含", "include", "require", "伪协议", "php://input", "data://"]),
            ("rce", ["eval(", "system(", "exec(", "passthru(", "shell_exec(", "命令执行", "rce"]),
            ("sqli", ["sql注入", "union select", "information_schema", "sqli", "sqlmap"]),
            ("ssti", ["ssti", "template", "jinja2", "twig", "{{", "模板注入"]),
            ("deserialization", ["反序列化", "unserialize", "serialize", "pop链", "wakeup"]),
            ("file_upload", ["文件上传", "upload", "webshell", "一句话木马"]),
            ("ssrf", ["ssrf", "gopher://", "dict://", "内网访问"]),
            ("xxe", ["xxe", "xml外部实体", "ENTITY"]),
            ("info_leak", ["源码泄露", ".git", ".svn", "备份文件", "目录遍历", "robots.txt"]),
            ("brute_force", ["爆破", "弱口令", "字典", "brute"]),
        ]

        for path_name, keywords in path_patterns:
            if any(kw in output_lower for kw in keywords):
                return path_name

        return None

    # ── Response extraction ──────────────────────────────

    @staticmethod
    def _extract_response(message) -> str:
        """Extract the actual response text from an LLM message.
        
        Handles:
        1. Normal content (no thinking)
        2. Content with inline <thinking> tags (open/closed)
        3. Separate reasoning_content field (DeepSeek R1, etc.)
        
        Returns the response text with thinking tags preserved for
        later processing by format_think_tags/strip_think_tags.
        """
        content = message.content or ""
        
        # Check for separate reasoning_content field (DeepSeek R1, etc.)
        # Some providers return thinking in reasoning_content, separate from content
        reasoning = getattr(message, "reasoning_content", None) or ""
        if reasoning and not content:
            # Model put all thinking in reasoning_content, content is empty
            # Prepend thinking as a <thinking> block so format_think_tags can handle it
            content = f"<thinking>\n{reasoning}\n</thinking>\n"
        elif reasoning and content:
            # Model has both reasoning and content
            # Prepend reasoning as a <thinking> block
            content = f"<thinking>\n{reasoning}\n</thinking>\n{content}"
        
        return content

    # ── LLM call methods ────────────────────────────────────────────

    async def _call_llm(self, system_prompt: str) -> str:
        """Call the LLM with the current context and system prompt (single turn)."""
        client = self._get_client()

        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(self.context.get_messages())

        # Build MCP tools as function definitions if available
        tools = self._build_openai_tools()

        kwargs = {
            "model": self.config.llm.model,
            "messages": messages,
            "max_tokens": self.config.llm.max_tokens,
            "temperature": self.config.llm.temperature,
        }

        if tools:
            kwargs["tools"] = tools

        # Provider-specific parameter handling
        provider = self.config.llm.provider.lower()
        if provider == "openai" and "o1" in self.config.llm.model.lower():
            kwargs["reasoning_effort"] = self.config.llm.reasoning_effort
            kwargs.pop("temperature", None)

        # Use asyncio to run sync OpenAI call
        import asyncio
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: client.chat.completions.create(**kwargs),
        )

        choice = response.choices[0]

        # Handle tool calls
        if choice.message.tool_calls:
            return await self._handle_tool_calls(choice.message)

        return self._extract_response(choice.message)

    async def _call_llm_auto(self, system_prompt: str, round_context: str) -> str:
        """Call the LLM in auto-pentest mode with round context appended.

        The round context is injected as the last user message to give
        the LLM awareness of the loop state.

        IMPORTANT: Tool call results are persisted to self.context so that
        subsequent rounds retain memory of what was discovered.
        """
        client = self._get_client()

        messages = [{"role": "system", "content": system_prompt}]

        # Add conversation history
        messages.extend(self.context.get_messages())

        # Append round context as a user message to drive the LLM
        messages.append({"role": "user", "content": round_context})

        # Build MCP tools as function definitions if available
        tools = self._build_openai_tools()

        kwargs = {
            "model": self.config.llm.model,
            "messages": messages,
            "max_tokens": self.config.llm.max_tokens,
            "temperature": self.config.llm.temperature,
        }

        if tools:
            kwargs["tools"] = tools

        # Provider-specific parameter handling
        provider = self.config.llm.provider.lower()
        if provider == "openai" and "o1" in self.config.llm.model.lower():
            kwargs["reasoning_effort"] = self.config.llm.reasoning_effort
            kwargs.pop("temperature", None)

        # Use asyncio to run sync OpenAI call
        import asyncio
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: client.chat.completions.create(**kwargs),
        )

        choice = response.choices[0]

        # Handle tool calls — execute them and feed result back
        if choice.message.tool_calls:
            tool_results = await self._handle_tool_calls_with_results(choice.message)

            # Build the assistant message dict with tool_calls for the conversation
            assistant_msg = {
                "role": "assistant",
                "content": choice.message.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in choice.message.tool_calls
                ],
            }
            messages.append(assistant_msg)

            for tool_result in tool_results:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_result["tool_call_id"],
                    "content": tool_result["content"],
                })

            # ★ Persist tool call results to context so later rounds remember them
            tool_summary_parts = []
            for tc in choice.message.tool_calls:
                tool_summary_parts.append(f"调用工具: {tc.function.name}({tc.function.arguments[:200]})")
            for tr in tool_results:
                content = tr['content']
                # ★ Improved truncation: keep head + tail (flag usually at the end)
                if len(content) > 1000:
                    content = content[:500] + "\n...[中间省略]...\n" + content[-500:]
                tool_summary_parts.append(f"工具结果: {content}")
            self.context.add_assistant_message(" | ".join(tool_summary_parts))

            # Second LLM call with tool results
            try:
                kwargs["messages"] = messages
                response2 = await loop.run_in_executor(
                    None,
                    lambda: client.chat.completions.create(**kwargs),
                )
                final_text = self._extract_response(response2.choices[0].message)
                # Persist the follow-up LLM response too
                self.context.add_assistant_message(final_text)
                return final_text
            except Exception as e2:
                # If the follow-up call fails, return what we have
                return f"[tool results processed] 继续分析错误: {e2}"

        return self._extract_response(choice.message)

    async def _handle_tool_calls(self, message) -> str:
        """Handle tool calls from the LLM response (legacy single-turn)."""
        results = []
        for tool_call in message.tool_calls:
            func_name = tool_call.function.name
            func_args = self._safe_parse_tool_args(tool_call.function.arguments)

            # Route to MCP
            tool_result = await self._execute_mcp_tool(func_name, func_args)
            results.append(f"[tool:{func_name}] {tool_result}")

        return "\n".join(results)

    async def _handle_tool_calls_with_results(self, message) -> list[dict]:
        """Handle tool calls and return structured results for the conversation.

        Returns a list of dicts with tool_call_id and content, suitable for
        adding as tool role messages.
        """
        results = []
        for tool_call in message.tool_calls:
            func_name = tool_call.function.name
            # Robust JSON parsing — LLM sometimes returns truncated/malformed JSON
            func_args = self._safe_parse_tool_args(tool_call.function.arguments)

            # Route to MCP
            tool_result = await self._execute_mcp_tool(func_name, func_args)

            results.append({
                "tool_call_id": tool_call.id,
                "content": f"[tool:{func_name}] {tool_result}",
            })

        return results

    @staticmethod
    def _safe_parse_tool_args(arguments: Optional[str]) -> dict:
        """Safely parse tool call arguments JSON, with fallback for malformed input."""
        if not arguments:
            return {}
        try:
            return json.loads(arguments)
        except json.JSONDecodeError as e:
            # LLM sometimes generates truncated JSON — try to recover partial args
            # Attempt 1: try adding closing braces
            for suffix in ['"}', '"}]', '"}}', '"}}]', '"]', '}']:
                try:
                    return json.loads(arguments + suffix)
                except json.JSONDecodeError:
                    continue
            # Attempt 2: try extracting partial key-value pairs via regex
            partial = {}
            kv_pattern = r'"(\w+)"\s*:\s*"([^"]*?)"'
            for match in re.finditer(kv_pattern, arguments):
                partial[match.group(1)] = match.group(2)
            if partial:
                return partial
            # Give up — return empty dict so the loop can continue
            return {}

    async def _execute_mcp_tool(self, tool_name: str, args: dict) -> str:
        """Execute a tool call via MCP manager or built-in tools."""
        # Built-in Python code executor
        if tool_name == "python_execute":
            return await self._execute_python(args)

        # Built-in skill reference loader
        if tool_name == "load_skill_reference":
            try:
                from vulnclaw.skills.loader import load_skill_reference
                skill_name = args.get("skill_name", "")
                ref_name = args.get("reference_name", "")
                content = load_skill_reference(skill_name, ref_name)
                if content:
                    return content
                return f"[!] 参考文档未找到: {skill_name}/{ref_name}"
            except Exception as e:
                return f"[!] 加载参考文档错误: {e}"

        # Built-in crypto toolkit
        if tool_name == "crypto_decode":
            try:
                from vulnclaw.skills.crypto_tools import execute as crypto_execute
                operation = args.get("operation", "")
                input_str = args.get("input", "")
                # Build kwargs from optional params
                kwargs = {}
                for key in ("key", "iv", "shift", "secret", "header", "algorithm"):
                    if key in args and args[key]:
                        kwargs[key] = args[key]
                        # Convert shift to int
                        if key == "shift":
                            kwargs[key] = int(args[key])
                result = crypto_execute(operation=operation, input_str=input_str, **kwargs)
                if result.get("success"):
                    return f"[✓] {operation} 结果:\n{result['result']}"
                return f"[!] {operation} 失败: {result.get('error', '未知错误')}"
            except Exception as e:
                return f"[!] 加密工具执行错误: {e}"

        # Route to MCP manager
        if not self.mcp_manager:
            return f"[!] MCP 管理器未初始化，无法执行工具: {tool_name}"

        try:
            result = await self.mcp_manager.call_tool(tool_name, args)
            return str(result)
        except Exception as e:
            return f"[!] 工具执行错误 ({tool_name}): {e}"

    def _build_openai_tools(self) -> list[dict]:
        """Build OpenAI function calling schema from MCP tools + built-in tools."""
        tools = []

        # Built-in skill reference loader
        tools.append({
            "type": "function",
            "function": {
                "name": "load_skill_reference",
                "description": "加载指定 Skill 的参考文档，获取详细的渗透测试方法论、工作流或命令参考。当系统提示中提到'可用参考文档'时，使用此工具获取具体内容。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "skill_name": {
                            "type": "string",
                            "description": "Skill 名称，如 client-reverse, web-security-advanced, ai-mcp-security, intranet-pentest-advanced, pentest-tools, rapid-checklist, crypto-toolkit, ctf-web, ctf-crypto, ctf-misc, osint-recon",
                        },
                        "reference_name": {
                            "type": "string",
                            "description": "参考文档文件名，如 02-client-api-reverse-and-burp.md, web-injection.md, encoding-cheatsheet.md",
                        },
                    },
                    "required": ["skill_name", "reference_name"],
                },
            },
        })

        # Built-in Python code executor
        tools.append({
            "type": "function",
            "function": {
                "name": "python_execute",
                "description": (
                    "执行 Python 代码片段。用于：构造复杂 HTTP 请求并解析响应、"
                    "做编码转换和数据处理、批量测试不同 payload、比较响应差异、"
                    "执行数学计算等。代码在受限环境中执行，超时 30 秒。"
                    "预装库：requests, beautifulsoup4, pycryptodome, base64, json, re 等。"
                    "重要：构造 HTTP 请求时请使用此工具而非猜测响应内容。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "要执行的 Python 代码。支持多行，可 import 标准库和 requests/bs4 等。",
                        },
                        "purpose": {
                            "type": "string",
                            "description": "简要说明执行目的（用于审计日志），如'构造HTTP请求测试弱比较绕过'",
                        },
                    },
                    "required": ["code"],
                },
            },
        })

        # Built-in crypto toolkit
        tools.append({
            "type": "function",
            "function": {
                "name": "crypto_decode",
                "description": (
                    "编码解码与加解密工具。遇到 base64/hex/URL/HTML/Unicode 编码字符串、"
                    "需要计算哈希、解密 AES/DES、解析 JWT 等场景时调用此工具。"
                    "重要：不要自行脑补解码结果，始终使用此工具确保准确性。"
                    "支持操作：base64_encode/decode, base32_encode/decode, base58_encode/decode, "
                    "hex_encode/decode, url_encode/decode, html_encode/decode, unicode_encode/decode, "
                    "rot13_encode/decode, caesar_encode/decode, morse_encode/decode, "
                    "md5_hash, sha1_hash, sha256_hash, sha512_hash, "
                    "aes_encrypt/decrypt, jwt_decode/encode, auto_decode"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "operation": {
                            "type": "string",
                            "description": (
                                "操作名称。编码: base64_encode, base32_encode, base58_encode, hex_encode, "
                                "url_encode, html_encode, unicode_encode, rot13_encode, caesar_encode, morse_encode. "
                                "解码: base64_decode, base32_decode, base58_decode, hex_decode, url_decode, "
                                "html_decode, unicode_decode, rot13_decode, caesar_decode, morse_decode, auto_decode. "
                                "哈希: md5_hash, sha1_hash, sha256_hash, sha512_hash. "
                                "加密/解密: aes_encrypt, aes_decrypt. "
                                "JWT: jwt_decode, jwt_encode"
                            ),
                        },
                        "input": {
                            "type": "string",
                            "description": "待处理的输入字符串（待编码/解码/哈希/加密的文本）",
                        },
                        "key": {
                            "type": "string",
                            "description": "加密/解密密钥（AES/DES 需要，16/24/32字节）",
                        },
                        "iv": {
                            "type": "string",
                            "description": "AES 初始化向量（16字节，可选）",
                        },
                        "shift": {
                            "type": "integer",
                            "description": "Caesar 密码位移量（默认3，解码时不提供则暴力所有位移）",
                        },
                        "secret": {
                            "type": "string",
                            "description": "JWT 签名密钥",
                        },
                    },
                    "required": ["operation", "input"],
                },
            },
        })

        # MCP tools
        if self.mcp_manager:
            for schema in self.mcp_manager.get_tool_schemas():
                tool = {
                    "type": "function",
                    "function": {
                        "name": schema.get("name", ""),
                        "description": schema.get("description", ""),
                        "parameters": schema.get("inputSchema", {
                            "type": "object",
                            "properties": {},
                        }),
                    },
                }
                tools.append(tool)

        return tools

    # ── Python code executor ─────────────────────────────────────────

    # Blocked patterns for sandbox safety
    _BLOCKED_PATTERNS = [
        r"os\.\s*system\s*\(",
        r"subprocess\.\s*Popen\s*\(",
        r"shutil\.\s*rmtree\s*\(",
        r"__import__\s*\(\s*['\"]os['\"]",
        r"open\s*\(\s*['\"].*vulnclaw.*config",
        r"open\s*\(\s*['\"].*\.vulnclaw",
    ]

    async def _execute_python(self, args: dict) -> str:
        """Execute a Python code snippet in a sandboxed subprocess.

        The code runs with a 30-second timeout. stdout and stderr are
        captured and returned to the LLM.
        """
        code = args.get("code", "")
        purpose = args.get("purpose", "")

        if not code.strip():
            return "[!] 代码为空，未执行"

        # Sandbox safety: block dangerous patterns
        for pattern in self._BLOCKED_PATTERNS:
            if re.search(pattern, code):
                return f"[!] 代码包含被禁止的操作模式: {pattern}，出于安全原因拒绝执行"

        # Write code to a temp file and execute it
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf-8"
            ) as f:
                # Prepend common imports for convenience
                preamble = (
                    "import sys, json, re, os, base64, hashlib, itertools, "
                    "collections, datetime, struct, binascii, textwrap\n"
                    "try:\n"
                    "    import requests\n"
                    "except ImportError:\n"
                    "    pass\n"
                    "try:\n"
                    "    from bs4 import BeautifulSoup\n"
                    "except ImportError:\n"
                    "    pass\n"
                    "try:\n"
                    "    from Crypto.Cipher import AES\n"
                    "except ImportError:\n"
                    "    pass\n"
                    "\n"
                )
                f.write(preamble)
                f.write(code)
                tmp_path = f.name

            # Execute with timeout
            import asyncio
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    [sys.executable, tmp_path],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                    cwd=tempfile.gettempdir(),
                    env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                ),
            )

            # Clean up temp file
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

            output_parts = []
            if result.stdout:
                output_parts.append(result.stdout)
            if result.stderr:
                # Filter out import warnings
                stderr_lines = [
                    line for line in result.stderr.splitlines()
                    if "ImportError" not in line and "No module named" not in line
                ]
                if stderr_lines:
                    output_parts.append("[stderr]\n" + "\n".join(stderr_lines))

            if not output_parts:
                return "[✓] 代码执行成功，无输出"

            output = "\n".join(output_parts)
            # Truncate if too long
            if len(output) > 8000:
                output = output[:4000] + "\n...[中间省略]...\n" + output[-4000:]

            return f"[✓] Python 执行结果:\n{output}"

        except subprocess.TimeoutExpired:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return "[!] Python 执行超时（30秒），请简化代码或分步执行"
        except Exception as e:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return f"[!] Python 执行错误: {e}"

    def _update_recon_dimension_completion(self, response: str) -> None:
        """Auto-detect which recon dimensions have been explored based on tool results.

        Only checks tool results (notes and executed_steps from real tool calls),
        NOT the LLM's reasoning text.

        This prevents false positives where python_execute code snippets contain
        generic keywords like "github.com" or "email" that would otherwise
        falsely mark the personnel dimension as complete.

        Once a dimension is marked complete, it stays complete.
        """
        # Only check tool results — these are real observations
        tool_notes = " ".join(self.context.state.notes[-10:]).lower()
        tool_steps = " ".join(self.context.state.executed_steps[-10:]).lower()
        tool_context = f"{tool_notes} {tool_steps}"

        # Do NOT include LLM response text — it contains reasoning, not results.
        # A python_execute code snippet with "github.com" in it should NOT
        # be treated as actually performing GitHub API research.

        for dim, keywords in _RECON_DIM_KEYWORDS.items():
            if dim == "personnel" and not self.context.state.recon_dimension4_active:
                continue
            if not self.context.state.recon_dimensions_completed.get(dim, False):
                if any(kw in tool_context for kw in keywords):
                    self.context.state.mark_recon_dimension(dim)

    def _parse_findings(self, response: str) -> None:
        """Parse vulnerability findings and key discoveries from LLM response."""
        from vulnclaw.agent.context import VulnerabilityFinding

        # Simple heuristic: look for severity markers
        patterns = [
            (r'\[Critical\]\s*(.+?)(?:\n|$)', "Critical"),
            (r'\[High\]\s*(.+?)(?:\n|$)', "High"),
            (r'\[Medium\]\s*(.+?)(?:\n|$)', "Medium"),
            (r'\[Low\]\s*(.+?)(?:\n|$)', "Low"),
        ]

        for pattern, severity in patterns:
            matches = re.findall(pattern, response)
            for match in matches:
                self.context.state.add_finding(VulnerabilityFinding(
                    title=match.strip(),
                    severity=severity,
                ))

        # Extract key discoveries and record as notes for context persistence
        discovery_markers = [
            r'\[\+\]\s*(.+?)(?:\n|$)',        # [+] findings
            r'发现[：:]\s*(.+?)(?:\n|$)',      # 发现: xxx
            r'(flag\{[^}]+\})',               # flag{...}
            r'(NSSCTF\{[^}]+\})',             # NSSCTF{...}
            r'(CTF\{[^}]+\})',                # CTF{...}
        ]
        for pattern in discovery_markers:
            matches = re.findall(pattern, response, re.IGNORECASE)
            for match in matches:
                note = match.strip()[:200]
                # Avoid duplicate notes
                if note and note not in self.context.state.notes:
                    self.context.state.add_note(note)

        # ★ Auto-extract confirmed facts (verified by tool output)
        confirmed_markers = [
            r'已确认[：:]\s*(.+?)(?:\n|$)',
            r'确认[：:]\s*(.+?)(?:\n|$)',
            r'验证成功[：:]\s*(.+?)(?:\n|$)',
            r'\[✅\]\s*(.+?)(?:\n|$)',
        ]
        for pattern in confirmed_markers:
            matches = re.findall(pattern, response, re.IGNORECASE)
            for match in matches:
                fact = match.strip()[:200]
                if fact and hasattr(self.context.state, 'add_confirmed_fact'):
                    self.context.state.add_confirmed_fact(fact)

        # ★ Auto-extract unverified assumptions from LLM output
        assumption_markers = [
            r'假设[：:]\s*(.+?)(?:\n|$)',
            r'推测[：:]\s*(.+?)(?:\n|$)',
        ]
        for pattern in assumption_markers:
            matches = re.findall(pattern, response, re.IGNORECASE)
            for match in matches:
                assumption = match.strip()[:200]
                if assumption and hasattr(self.context.state, 'add_assumption'):
                    self.context.state.add_assumption(assumption)
