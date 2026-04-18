"""VulnClaw Agent Core — the main AI agent loop with tool calling."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.agent.context import ContextManager, PentestPhase, SessionState
from vulnclaw.agent.prompts import build_system_prompt, AUTO_PENTEST_INSTRUCTION


@dataclass
class AgentResult:
    """Result from a single agent turn."""

    output: str = ""
    target: Optional[str] = None
    phase: Optional[str] = None
    tool_calls: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    should_continue: bool = True  # Whether the agent should keep looping


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

        prompt = build_system_prompt(
            target=target or self.context.state.target,
            phase=phase,
            skill_context=skill_context,
            mcp_tools=mcp_tools,
        )

        # Add auto-pentest instruction when in autonomous mode
        if auto_mode:
            prompt += "\n\n" + AUTO_PENTEST_INSTRUCTION

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
        """Process a user message and return agent response (single turn)."""
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

                # Detect phase transitions from LLM output
                new_phase = self._detect_phase_from_output(response_text)
                if new_phase and new_phase != self.context.state.phase:
                    self.context.state.advance_phase(new_phase)
                    result.phase = new_phase.value

                # Check if agent signals completion
                result.should_continue = not self._is_completion_signal(response_text)

                # Record step
                self.context.state.add_step(f"Round {round_num}: {response_text[:100]}...")

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
            recent_steps = state.executed_steps[-5:]
            steps_summary = f"\n最近执行步骤: {len(state.executed_steps)} 个总计"
            for s in recent_steps:
                steps_summary += f"\n  - {s[:150]}"

        recon_summary = ""
        if state.recon_data:
            recon_summary = f"\n侦察数据: {list(state.recon_data.keys())}"

        # Include notes (important for CTF hints)
        notes_summary = ""
        if state.notes:
            notes_summary = f"\n重要笔记: {'; '.join(state.notes[-5:])}"

        return (
            f"\n\n[自主循环 Round {round_num}/{max_rounds}]"
            f"\n当前目标: {state.target or '未设置'}"
            f"\n当前阶段: {state.phase.value}"
            f"{findings_summary}"
            f"{steps_summary}"
            f"{recon_summary}"
            f"{notes_summary}"
            f"\n\n请基于当前状态和之前所有发现决定下一步操作，持续推进渗透测试。"
            f"\n注意：不要重复之前已经做过的操作，专注于推进到下一步。"
            f"\n如果发现重要线索或完成测试，在回复末尾添加 [DONE] 标记。"
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

        return choice.message.content or ""

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
                tool_summary_parts.append(f"工具结果: {tr['content'][:500]}")
            self.context.add_assistant_message(" | ".join(tool_summary_parts))

            # Second LLM call with tool results
            try:
                kwargs["messages"] = messages
                response2 = await loop.run_in_executor(
                    None,
                    lambda: client.chat.completions.create(**kwargs),
                )
                final_text = response2.choices[0].message.content or ""
                # Persist the follow-up LLM response too
                self.context.add_assistant_message(final_text)
                return final_text
            except Exception as e2:
                # If the follow-up call fails, return what we have
                return f"[tool results processed] 继续分析错误: {e2}"

        return choice.message.content or ""

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
        """Execute a tool call via MCP manager or built-in skill loader."""
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
                            "description": "Skill 名称，如 client-reverse, web-security-advanced, ai-mcp-security, intranet-pentest-advanced, pentest-tools, rapid-checklist",
                        },
                        "reference_name": {
                            "type": "string",
                            "description": "参考文档文件名，如 02-client-api-reverse-and-burp.md, web-injection.md",
                        },
                    },
                    "required": ["skill_name", "reference_name"],
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
