"""VulnClaw Agent Core — the main AI agent loop with tool calling."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable, Optional


from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.agent.context import ContextManager, PentestPhase, SessionState
from vulnclaw.agent.prompts import build_system_prompt, AUTO_PENTEST_INSTRUCTION, RECON_INSTRUCTION
from vulnclaw.agent.runtime_state import AgentResult, PersistentCycleResult, RuntimeState
from vulnclaw.agent.think_filter import strip_think_tags, format_think_tags
from vulnclaw.agent.finding_parser import FindingParser
from vulnclaw.agent.llm_client import call_llm, call_llm_auto, extract_response
from vulnclaw.agent.loop_controller import auto_pentest as run_auto_pentest, persistent_pentest as run_persistent_pentest
from vulnclaw.agent.recon_tracker import RECON_MIN_ROUNDS, update_recon_dimension_completion
from vulnclaw.agent.tool_call_manager import (


    handle_tool_calls,
    handle_tool_calls_with_results,
    safe_parse_tool_args,
)
from vulnclaw.agent.builtin_tools import (


    BLOCKED_PATTERNS,
    RESERVED_IP_RANGES,
    build_openai_tools,
    execute_mcp_tool,
    execute_python,
    execute_nmap,
    is_reserved_ip,
    parse_nmap_xml,
    validate_scan_target,
)

# Optional KB integration — gracefully degrade if KB data is unavailable
try:
    from vulnclaw.kb.retriever import KnowledgeRetriever
except Exception:
    KnowledgeRetriever = None






class AgentCore:




    """Core AI agent that orchestrates LLM calls and tool execution."""

    _RUNTIME_FIELDS = (
        "auto_skill_input",
        "user_vuln_hint",
        "user_vuln_hint_rounds",
        "claimed_flag",
        "flag_verified",
        "flag_claim_count",
        "post_flag_rounds",
        "is_recon_phase",
        "rounds_without_progress",
        "last_findings_count",
        "last_notes_count",
        "last_steps_count",
        "python_timeout_rounds",
        "seen_step_signatures",
        "current_attack_path",
        "same_path_fail_count",
        "path_switch_forced",
        "failed_targets",
        "blocked_targets",
        "unverified_assumptions",
        "is_ctf_mode",
        "consecutive_errors",
    )

    def __init__(self, config: VulnClawConfig, mcp_manager: Any = None) -> None:
        self.config = config
        self.mcp_manager = mcp_manager
        self.context = ContextManager()
        self._client = None
        self.runtime = RuntimeState()
        self._reset_runtime_state()
        # Optional KB retriever — lazily initialized on first use
        self._kb_retriever: Any = None
        self._finding_parser = FindingParser(self.context, self.runtime)


    def __getattr__(self, name: str) -> Any:
        """Backward-compatible bridge for legacy _runtime field access."""
        if name.startswith("_"):
            runtime_name = name[1:]
            if runtime_name in self._RUNTIME_FIELDS:
                return getattr(self.runtime, runtime_name)
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")

    def __setattr__(self, name: str, value: Any) -> None:
        """Backward-compatible bridge for legacy _runtime field assignment."""
        if name.startswith("_"):
            runtime_fields = type(self).__dict__.get("_RUNTIME_FIELDS", ())
            runtime = self.__dict__.get("runtime")
            runtime_name = name[1:]
            if runtime is not None and runtime_name in runtime_fields:
                setattr(runtime, runtime_name, value)
                return
        super().__setattr__(name, value)

    @property
    def session_state(self) -> SessionState:

        """Access current session state."""
        return self.context.state

    def reset_context(self) -> None:
        """Reset agent context and runtime loop state."""
        self.context.reset()
        self._reset_runtime_state()

    def _reset_runtime_state(
        self,
        user_input: str = "",
        detected_phase: Optional[PentestPhase] = None,
    ) -> None:
        """Reset per-run runtime state to avoid cross-run contamination."""
        user_lower = user_input.lower() if user_input else ""
        self.runtime = RuntimeState(
            auto_skill_input=user_input,
            user_vuln_hint=self._extract_user_vuln_hint(user_input) if user_input else "",
            is_recon_phase=detected_phase == PentestPhase.RECON,
            is_ctf_mode=any(
                kw in user_lower for kw in ["ctf", "flag", "夺旗", "解题", "找flag", "找出flag"]
            ),
        )
        self.runtime.user_vuln_hint_rounds = 3 if self.runtime.user_vuln_hint else 0

        self.context.state.recon_dimensions_completed = {
            "server": False,
            "website": False,
            "domain": False,
            "personnel": False,
        }
        social_engineering_keywords = [
            "社会工程", "社工", "人员信息", "作者追踪", "人物追踪", "人物画像",
            "osint", "情报", "作者", "调查",
        ]
        self.context.state.recon_dimension4_active = (
            self.runtime.is_recon_phase
            and any(kw in user_lower for kw in social_engineering_keywords)
        )
        # Re-bind finding parser to the new runtime object
        self._finding_parser = FindingParser(self.context, self.runtime)

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

        # ★ Inject knowledge-base context when available
        kb_context = self._build_kb_context(user_input)
        if kb_context:
            prompt += "\n\n" + kb_context

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

    def _build_kb_context(self, user_input: Optional[str] = None) -> str:
        """Build knowledge-base context for prompt injection.

        Retrieves relevant CVEs, techniques, and WAF bypass info based on
        current session state and user input. Returns empty string if KB
        is unavailable or no relevant entries are found.
        """
        if KnowledgeRetriever is None:
            return ""

        try:
            if self._kb_retriever is None:
                self._kb_retriever = KnowledgeRetriever()
        except Exception:
            return ""

        entries: list[dict[str, Any]] = []

        # 1. Search by service versions from recon data
        recon = getattr(self.context.state, "recon_data", {})
        services = recon.get("services", [])
        for svc in services[:3]:
            parts = str(svc).lower().split("/")
            name = parts[0]
            version = parts[1] if len(parts) > 1 else ""
            entries.extend(self._kb_retriever.search_by_service(name, version))

        # 2. Search by vulnerability types from current findings
        for finding in self.context.state.findings[:3]:
            vuln_type = (finding.vuln_type or "").lower()
            if vuln_type:
                entries.extend(self._kb_retriever.search_technique(vuln_type))

        # 3. If user input mentions WAF, retrieve bypass techniques
        if user_input and "waf" in user_input.lower():
            entries.extend(self._kb_retriever.get_waf_bypass())

        # 4. Search by keywords in user input (for technique hints)
        if user_input:
            for keyword in ("sqli", "xss", "rce", "lfi", "ssrf", "csrf", "deserialization"):
                if keyword in user_input.lower():
                    entries.extend(self._kb_retriever.search_technique(keyword))

        # Deduplicate by id and format
        seen_ids: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for e in entries:
            eid = e.get("id", e.get("title", ""))
            if eid and eid not in seen_ids:
                seen_ids.add(eid)
                deduped.append(e)

        if not deduped:
            return ""

        formatted = self._kb_retriever.format_for_prompt(deduped, max_entries=5)
        return (
            "## 知识库参考（相关 CVE / 利用技巧 / 绕过方法）\n"
            "以下信息来自本地安全知识库，供参考使用：\n\n"
            f"{formatted}\n"
        )

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

    def _extract_user_vuln_hint(self, user_input: str) -> str:
        """Extract explicit vulnerability hints from user input.

        When the user says "这个点有SQL注入，测试一下" or "帮我测一下XSS"，
        returns a directive telling LLM to test that specific vuln immediately.
        Returns "" if no explicit hint found.
        """
        # Known vulnerability keywords to look for
        vuln_keywords = [
            "SQL注入", "SQLi", "XSS", "RCE", "命令注入",
            "文件包含", "路径遍历", "LFI", "RFI",
            "SSRF", "CSRF", "弱口令", "暴力破解",
            "认证绕过", "未授权", "信息泄露", "敏感信息泄露",
        ]

        user_lower = user_input.lower()
        found_vulns = [v for v in vuln_keywords if v.lower() in user_lower]
        if not found_vulns:
            return ""

        # Try to extract URL/path from user input
        url_match = re.search(r'https?://\S+', user_input)
        path_match = re.search(r'/[\w\-./?=&%#]+', user_input)
        target = url_match.group(0) if url_match else (path_match.group(0) if path_match else "")

        vuln_str = "/".join(found_vulns[:3])
        if target:
            # Provide specific payload templates for each vuln type
            payload_examples = self._get_payload_examples(found_vulns, target)
            directive = (
                f"【用户明确提示 — 第1轮】\n"
                f"用户明确告诉你 【{target}】 存在 【{vuln_str}】 漏洞。\n"
                f"\n"
                f"→ 你必须立即构造并发送 PoC 测试请求！\n"
                f"→ 用 fetch 工具直接发送请求，观察真实响应！\n"
                f"→ 不要先探索路径、不要先做信息收集，直接测漏洞！\n"
                f"\n"
                f"{payload_examples}"
            )
        else:
            directive = (
                f"【用户明确提示】\n"
                f"用户要求你测试 【{vuln_str}】 漏洞。\n"
                f"→ 立即基于已发现的目标信息构造 PoC 测试，不要先做额外信息收集！"
            )
        return directive

    @staticmethod
    def _get_payload_examples(found_vulns: list[str], target: str) -> str:
        """Return concrete PoC payload examples for the given vulnerability types."""
        lines = ["【PoC payload 示例】"]
        for v in found_vulns[:2]:  # limit to 2 vuln types to avoid overload
            if "SQL" in v:
                lines.append(f"SQL注入测试（布尔盲注）:")
                lines.append(f"  GET {target}?id=1' AND 1=1--  → 观察响应长度")
                lines.append(f"  GET {target}?id=1' AND 1=2--  → 长度是否不同？")
                lines.append(f"SQL注入测试（报错注入）:")
                lines.append(f"  GET {target}?id=1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--")
            elif "XSS" in v:
                lines.append(f"XSS测试:")
                lines.append(f"  GET {target}?q=<script>alert(1)</script>  → 页面是否回显该内容")
                lines.append(f"  GET {target}?q=<img src=x onerror=alert(1)>")
            elif "RCE" in v or "命令注入" in v:
                lines.append(f"RCE/命令注入测试:")
                lines.append(f"  GET {target}?cmd=whoami  → 观察是否有命令输出")
                lines.append(f"  GET {target}?c=whoami  → 不同参数名都试")
            elif "文件包含" in v or "路径遍历" in v:
                lines.append(f"文件包含/路径遍历测试:")
                lines.append(f"  GET {target}?f=/etc/passwd  → 读取系统文件")
                lines.append(f"  GET {target}?f=../../../../etc/passwd")
            elif "SSRF" in v:
                lines.append(f"SSRF测试:")
                lines.append(f"  GET {target}?url=http://127.0.0.1  → 是否有响应")
                lines.append(f"  GET {target}?url=http://169.254.169.254/latest/meta-data/")
        return "\n".join(lines[:12])  # max 12 lines

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
            self._finding_parser.parse(response_text)

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
        """Autonomous penetration test loop."""
        return await run_auto_pentest(self, user_input, target, max_rounds, on_step)


    def _build_round_context(self, round_num: int, max_rounds: int) -> str:
        """Build context string for the current round in auto loop."""
        state = self.context.state
        findings_summary = ""
        if state.findings:
            findings_summary = f"\n已发现漏洞: {len(state.findings)} 个"
            for f in state.findings[-5:]:  # Show last 5 findings
                findings_summary += f"\n  - [{f.severity}] {f.title}: {f.evidence[:100]}"

        # ★ User vuln hint injection: when user explicitly hints "这个点有XX漏洞"
        # inject a direct "test it now" directive for the first few rounds
        user_hint_directive = ""
        if round_num <= self._user_vuln_hint_rounds and self._user_vuln_hint:
            user_hint_directive = (
                f"\n\n{'='*50}\n"
                f"【用户明确提示 — 第 {round_num}/{self._user_vuln_hint_rounds} 轮】\n"
                f"{self._user_vuln_hint}\n"
                f"{'='*50}\n"
            )
            self._user_vuln_hint_rounds -= 1  # decrement so it expires after N rounds


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
        same_path_fails = self._same_path_fail_count

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

        # ★ Python timeout tracking — warn when previous rounds had Python timeouts
        python_timeout_warning = ""
        python_timeout_rounds = self._python_timeout_rounds

        if python_timeout_rounds >= 1:
            python_timeout_warning = (
                f"\n\n⚠️ **代码执行警告**：上轮 Python 脚本超时了。"
                f"\n禁止写超过 10 行的复杂脚本。"
                f"\n优先使用已有的工具（fetch/python_execute）而非自己写爬虫/解析代码。"
                f"\n禁止重复执行相同的大段脚本。"
            )

        # ★ Dead-loop detection — if no progress for multiple rounds
        dead_loop_warning = ""
        rounds_no_progress = self._rounds_without_progress
        stale_threshold = self.config.session.stale_rounds_threshold

        # ★ Target-level failure warning: if targets are blocked
        blocked_targets_warning = ""
        blocked_targets = self._blocked_targets
        if blocked_targets:

            blocked_targets_warning = (
                f"\n\n🚨 **目标不可访问警告**：以下目标已连续多次访问失败，禁止再次尝试："
                f"\n{chr(10).join(f'  ❌ {t} — 已确认不可达' for t in blocked_targets)}"
                f"\n\n你必须："
                f"\n1. 立即停止访问上述目标"
                f"\n2. 专注于其他存活的目标"
                f"\n3. 如果没有其他目标，切换到已确认漏洞的深入利用"
                f"\n4. 不要再浪费轮次尝试连接不可达的目标"
            )

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
        claimed_flag = self._claimed_flag
        flag_verified = self._flag_verified
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
        is_ctf = self._is_ctf_mode
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
        if self._is_recon_phase:
            dim_status_text = self.context.state.get_recon_status_text()
            is_complete = self.context.state.is_recon_complete()
            rounds_no_progress = self._rounds_without_progress

            recon_dim_status = (
                f"\n\n📊 信息收集维度完成度:"
                f"\n{dim_status_text}"
            )
            if not is_complete:
                recon_dim_status += (
                    f"\n\n🔴 信息收集未完成！还有维度未检查，禁止标记 [DONE]。"
                    f"\n请继续对未完成的维度执行检查，确保每个维度都至少做过一轮。"
                )
            elif (is_complete and rounds_no_progress >= 3) or \
                 (rounds_no_progress >= RECON_MIN_ROUNDS + 5):
                # ★ Force transition to exploitation — two trigger paths:
                #   Path A: all dims done + no new progress for 3+ rounds
                #   Path B (safety valve): no progress for RECON_MIN_ROUNDS+5 rounds
                #       even if dimensions aren't formally marked complete.
                #       This prevents the bug where dimension keywords never fire
                #       but LLM has clearly been doing recon for many rounds.
                output_dir = str(self.config.session.output_dir.resolve())
                if is_complete:
                    trigger_reason = f"所有维度均已完成 ✅，连续 {rounds_no_progress} 轮无新进展"
                else:
                    trigger_reason = f"连续 {rounds_no_progress} 轮无新进展（{RECON_MIN_ROUNDS}+5 安全阀）"
                recon_dim_status += (
                    f"\n\n🔴 ★★★ 侦察→利用阶段强制切换 ★★★\n"
                    f"{trigger_reason}。\n"
                    f"你必须立即切换到【漏洞利用阶段】，而不是继续收集信息或保存报告。\n\n"
                    f"★ 立即执行以下操作：\n"
                    f"1. 在回复中输出「切换到漏洞发现」或「阶段: vuln_discovery」\n"
                    f"2. 基于已收集的侦察结果（目标画像/旁站/API泄露等），\n"
                    f"   对最高价值的攻击面实施实际的漏洞利用\n"
                    f"3. 【禁止】继续保存侦察报告或调用信息收集类工具\n"
                    f"4. 【禁止】重复已有的发现，必须有新的实际验证步骤\n\n"
                    f"★ 输出目录（侦察报告由框架自动保存，不需要你手动保存）：\n"
                    f"   {output_dir}\n"
                    f"⚠️ 本次渗透的目标是【实际漏洞利用成功】，不是侦察报告！"
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
            f"\n输出目录: {self.config.session.output_dir.resolve()}"
            f"{user_hint_directive}"   # ★ 用户漏洞提示：前3轮注入，直接告诉 LLM 要测什么漏洞
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
            f"{python_timeout_warning}"
            f"{blocked_targets_warning}"
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
        """Persistent penetration test — runs cycles of auto_pentest until stopped."""
        return await run_persistent_pentest(
            self,
            user_input,
            target,
            rounds_per_cycle,
            max_cycles,
            auto_report,
            on_cycle_step,
            on_cycle_complete,
        )


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

    # ★ Target-level failure detection
    FAILED_ACCESS_PATTERNS = [
        "SSLError", "ReadTimeout", "连接超时", "连接失败",
        "502 Bad Gateway", "502", "503", "无法访问", "访问失败",
        "Connection refused", "ConnectionError", "TimeoutError",
        "Name or service not known", "No route to host",
        "SSL: CERTIFICATE_VERIFY_FAILED", "超时",
    ]

    def _track_failed_target(self, response_text: str) -> Optional[str]:
        """Track target-level failures and detect repeatedly failed targets.

        Returns the hostname of a blocked target if one is detected, else None.
        """
        # Extract hostname from the response
        import re
        hostname = None
        url_match = re.search(r'https?://([^\s/<>"\')\]]+)', response_text)
        if url_match:
            hostname = url_match.group(1)

        if not hostname:
            return None

        # Check if this round's output indicates a failed access attempt
        is_failed_access = any(pattern in response_text for pattern in self.FAILED_ACCESS_PATTERNS)

        if is_failed_access:
            self._failed_targets[hostname] = self._failed_targets.get(hostname, 0) + 1
            # After 3 accumulated failures, block the target
            if self._failed_targets[hostname] >= 3:
                self._blocked_targets.add(hostname)
                return hostname
        else:
            # Success or different action — decrement counter (don't reset to 0)
            # A single success shouldn't erase all failure history for this target.
            # If the target was previously unreachable, partial recovery is noted
            # but the history persists until fully cleared.
            if hostname in self._failed_targets and self._failed_targets[hostname] > 0:
                self._failed_targets[hostname] -= 1

        return None

    def _is_meaningful_step(self, step: str) -> bool:
        """Check if a step represents meaningful progress (not just a failed retry).

        Only steps with actual discoveries or confirmations count as progress.
        A step is considered NOT meaningful only when it is a PURE failure —
        i.e., it mentions failure indicators AND has no progress indicators at all.
        If a step has BOTH failure and progress keywords (e.g. "XSS测试超时但发现新路径"),
        it is still meaningful because progress was made.
        """
        FAILURE_ONLY_KEYWORDS = [
            "SSLError", "ReadTimeout", "连接超时", "连接失败",
            "502 Bad Gateway", "无法访问", "访问失败",
            "Connection refused", "ConnectionError", "TimeoutError",
            "请求失败",
        ]
        PROGRESS_KEYWORDS = [
            "发现", "确认", "漏洞", "端口", "路径",
            "flag", "成功", "CVE", "泄露", "绕过",
            "验证通过", "已确认",
        ]

        has_progress = any(kw in step for kw in PROGRESS_KEYWORDS)
        if has_progress:
            return True  # Any progress keyword makes it meaningful

        has_failure = any(kw in step for kw in FAILURE_ONLY_KEYWORDS)
        if has_failure:
            return False  # Pure failure with no progress — not meaningful

        return True  # Neither failure nor progress keywords — assume meaningful

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
        return extract_response(message)


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

        if response is None or not response.choices:
            return "[!] LLM API 异常响应（配额耗尽/限流/网络错误），请稍后重试"

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
        return await call_llm_auto(self, system_prompt, round_context)


    async def _handle_tool_calls(self, message) -> str:
        """Handle tool calls from the LLM response (legacy single-turn)."""
        return await handle_tool_calls(self, message)


    async def _handle_tool_calls_with_results(self, message) -> tuple[list[dict], list[str]]:
        """Handle tool calls with deduplication and rate limiting.

        Returns:
            (results, skipped_info) — executed results and info about skipped calls.
        """
        return await handle_tool_calls_with_results(self, message)


    async def _generate_attack_summary(self) -> str:
        """Generate a detailed attack path summary for the cycle report.

        Provides all execution steps, notes, and findings to the LLM and asks
        for a detailed narrative of the attack chain with specific URLs/techniques.
        """
        state = self.context.state

        # Collect all execution steps
        steps = state.executed_steps[-30:] if state.executed_steps else []
        steps_text = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps)) if steps else "（无步骤记录）"

        # Collect all notes/observations
        notes = state.notes[-20:] if state.notes else []
        notes_text = "\n".join(f"- {n}" for n in notes) if notes else "（无观察记录）"

        # Findings with evidence
        findings = state.findings
        if findings:
            lines = []
            for f in findings:
                ev = (f.evidence or "")[:150].strip()
                lines.append(f"[{f.severity}] {f.title} | 证据: {ev or '无'}")
            findings_text = "\n".join(lines)
        else:
            findings_text = "无"

        prompt = (
            f"目标：{state.target or '?'}  |  当前阶段：{state.phase.value}\n"
            f"\n=== 已执行步骤 ===\n{steps_text}\n"
            f"\n=== 关键观察/结果 ===\n{notes_text}\n"
            f"\n=== 漏洞发现 ===\n{findings_text}\n\n"
            f"请输出一段详细的中文攻击路径叙事，包含以下要素：\n"
            f"1. 具体测试过的 URL/路径（如 https://target.com/admin/login）\n"
            f"2. 每步使用的具体技术/工具（如 SQLMap 盲注、目录枚举、nmap 端口扫描）\n"
            f"3. 关键响应特征（如差异长度155字节、HTTP 500错误回显）\n"
            f'4. 漏洞与攻击面的关联（如通过目录枚举发现 /manager/html，命中 CVE-2023-44487）\n'
            f"5. 子域名发现情况（如发现 api.target.com、cms.target.com 等）\n"
            f"格式要求：用自然段落叙事，不用列表，长度 200-400 字，纯中文，不含 <thinking> 标签。"
        )

        try:
            client = self._get_client()
            messages = [{"role": "user", "content": prompt}]
            response = client.chat.completions.create(
                model=self.config.llm.model,
                messages=messages,
                max_tokens=800,
                temperature=0.3,
            )
            if response and response.choices:
                raw = response.choices[0].message.content or ""
                # Strip any residual think tags from the summary itself
                return strip_think_tags(raw).strip()
        except Exception:
            pass
        return ""

    @staticmethod
    def _safe_parse_tool_args(arguments: Optional[str]) -> dict:
        """Safely parse tool call arguments JSON, with fallback for malformed input."""
        return safe_parse_tool_args(arguments)


    async def _execute_mcp_tool(self, tool_name: str, args: dict) -> str:
        """Execute a tool call via MCP manager or built-in tools."""
        return await execute_mcp_tool(self, tool_name, args)


    def _build_openai_tools(self) -> list[dict]:
        """Build OpenAI function calling schema from MCP tools + built-in tools."""
        return build_openai_tools(self.mcp_manager)


    # ── Python code executor ─────────────────────────────────────────

    _BLOCKED_PATTERNS = BLOCKED_PATTERNS

    async def _execute_nmap(self, args: dict) -> str:
        return await execute_nmap(self, args)

    # ── Reserved IP detection helpers ─────────────────────────────────

    _RESERVED_IP_RANGES = RESERVED_IP_RANGES

    def _is_reserved_ip(self, ip: str) -> tuple[bool, str]:
        return is_reserved_ip(ip)

    def _validate_scan_target(self, target: str) -> str:
        return validate_scan_target(target)

    def _parse_nmap_xml(self, xml_output: str, target: str) -> str:
        return parse_nmap_xml(xml_output, target)

    async def _execute_python(self, args: dict) -> str:
        return await execute_python(self, args)


    def _update_recon_dimension_completion(self, response: str) -> None:
        """Auto-detect which recon dimensions have been explored."""
        update_recon_dimension_completion(self, response)


