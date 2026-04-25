"""LLM client helpers for AgentCore."""

from __future__ import annotations

import asyncio
from typing import Any


def extract_response(message: Any) -> str:
    """Extract the actual response text from an LLM message.

    Handles:
    1. Normal content (no thinking)
    2. Content with inline <thinking> tags (open/closed)
    3. Separate reasoning_content field (DeepSeek R1, etc.)
    """
    content = message.content or ""
    reasoning = getattr(message, "reasoning_content", None) or ""
    if reasoning and not content:
        content = f"<thinking>\n{reasoning}\n</thinking>\n"
    elif reasoning and content:
        content = f"<thinking>\n{reasoning}\n</thinking>\n{content}"
    return content


async def call_llm(agent: Any, system_prompt: str) -> str:
    """Call the LLM with the current context and system prompt (single turn)."""
    client = agent._get_client()

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    tools = agent._build_openai_tools()

    kwargs = {
        "model": agent.config.llm.model,
        "messages": messages,
        "max_tokens": agent.config.llm.max_tokens,
        "temperature": agent.config.llm.temperature,
    }
    if tools:
        kwargs["tools"] = tools

    provider = agent.config.llm.provider.lower()
    if provider == "openai" and "o1" in agent.config.llm.model.lower():
        kwargs["reasoning_effort"] = agent.config.llm.reasoning_effort
        kwargs.pop("temperature", None)

    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(None, lambda: client.chat.completions.create(**kwargs))

    if response is None or not response.choices:
        return "[!] LLM API 异常响应（配额耗尽/限流/网络错误），请稍后重试"

    choice = response.choices[0]
    if choice.message.tool_calls:
        return await agent._handle_tool_calls(choice.message)
    return extract_response(choice.message)


async def call_llm_auto(agent: Any, system_prompt: str, round_context: str) -> str:
    """Call the LLM in auto-pentest mode with round context appended."""
    client = agent._get_client()

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    messages.append({"role": "user", "content": round_context})
    tools = agent._build_openai_tools()

    kwargs = {
        "model": agent.config.llm.model,
        "messages": messages,
        "max_tokens": agent.config.llm.max_tokens,
        "temperature": agent.config.llm.temperature,
    }
    if tools:
        kwargs["tools"] = tools

    provider = agent.config.llm.provider.lower()
    if provider == "openai" and "o1" in agent.config.llm.model.lower():
        kwargs["reasoning_effort"] = agent.config.llm.reasoning_effort
        kwargs.pop("temperature", None)

    loop = asyncio.get_event_loop()
    response = None
    for attempt in range(3):
        try:
            response = await loop.run_in_executor(None, lambda: client.chat.completions.create(**kwargs))
            break
        except Exception as e:
            err_str = str(e).lower()
            if attempt < 2 and any(kw in err_str for kw in ["overloaded", "529", "rate limit", "timeout", "timed out", "connection"]):
                await asyncio.sleep((attempt + 1) * 5)
                continue
            response = None
            break

    if response is None or not response.choices:
        return "[!] LLM API 异常响应（配额耗尽/限流/网络错误），请稍后重试"

    choice = response.choices[0]
    if choice.message.tool_calls:
        tool_results, skipped_info = await agent._handle_tool_calls_with_results(choice.message)

        executed_tcs = []
        for tc in tool_results:
            if not isinstance(tc, dict) or "tool_call" not in tc:
                import sys
                print(f"[!] 跳过异常工具结果: {type(tc).__name__} {str(tc)[:100]}", file=sys.stderr)
                continue
            executed_tcs.append(tc["tool_call"])

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
                for tc in executed_tcs
            ],
        }
        messages.append(assistant_msg)

        for tool_result in tool_results:
            if isinstance(tool_result, dict) and "tool_call_id" in tool_result:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_result["tool_call_id"],
                    "content": tool_result.get("content", ""),
                })

        tool_summary_parts = []
        for tc in executed_tcs:
            try:
                args_str = str(tc.function.arguments)[:200]
            except Exception:
                args_str = "<无法读取>"
            tool_summary_parts.append(f"调用工具: {tc.function.name}({args_str})")
        for tr in tool_results:
            content = tr.get("content", "") if isinstance(tr, dict) else str(tr)
            if len(content) > 1000:
                content = content[:500] + "\n...[中间省略]...\n" + content[-500:]
            tool_summary_parts.append(f"工具结果: {content}")
        if skipped_info:
            tool_summary_parts.append(f"⚠️ 本轮跳过: {'; '.join(skipped_info)}")
        agent.context.add_assistant_message(" | ".join(tool_summary_parts))

        try:
            kwargs["messages"] = messages
            response2 = await loop.run_in_executor(None, lambda: client.chat.completions.create(**kwargs))
            if response2 is None or not response2.choices:
                return "[tool results processed] 工具已执行完毕，但二次总结请求失败（API 异常），请继续分析"
            final_text = extract_response(response2.choices[0].message)
            agent.context.add_assistant_message(final_text)
            return final_text
        except Exception as e2:
            return f"[tool results processed] 继续分析错误: {e2}"

    return extract_response(choice.message)
