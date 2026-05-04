"""Dynamic system prompt assembly for AgentCore."""

from __future__ import annotations

from typing import Optional

from vulnclaw.agent.prompts import build_system_prompt, AUTO_PENTEST_INSTRUCTION, RECON_INSTRUCTION


def build_dynamic_system_prompt(
    *,
    target: Optional[str],
    phase: Optional[str],
    skill_context: Optional[str],
    mcp_tools: list[dict],
    enable_personnel_dim: bool,
    auto_mode: bool,
    user_input: Optional[str],
    kb_context: str,
) -> str:
    """Build the dynamic system prompt for one turn."""
    prompt = build_system_prompt(
        target=target,
        phase=phase,
        skill_context=skill_context,
        mcp_tools=mcp_tools,
        enable_personnel_dim=enable_personnel_dim,
    )

    if auto_mode:
        prompt += "\n\n" + AUTO_PENTEST_INSTRUCTION

    if user_input:
        recon_triggers = [
            "搜集", "收集", "信息收集", "侦察", "recon", "osint",
            "社会工程", "社工", "调查", "作者", "人物", "情报",
            "分析目标", "目标分析", "资产发现", "子域名",
        ]
        if any(trigger in user_input.lower() for trigger in recon_triggers):
            if enable_personnel_dim:
                prompt += "\n\n" + RECON_INSTRUCTION
            else:
                recon_no_personnel = RECON_INSTRUCTION.replace(
                    "### 维度四：人员信息 ⚡ 条件触发",
                    "### 维度四：人员信息 ⚡ 条件触发（本次未激活 — 用户未提及社工/人员追踪需求）",
                )
                recon_no_personnel = recon_no_personnel.replace(
                    "- [ ] 姓名 & 职务",
                    "- [x] 姓名 & 职务（未激活，跳过）",
                ).replace(
                    "- [ ] 生日 & 联系电话",
                    "- [x] 生日 & 联系电话（未激活，跳过）",
                ).replace(
                    "- [ ] 邮件地址",
                    "- [x] 邮件地址（未激活，跳过）",
                ).replace(
                    "- [ ] 社交媒体账号（B站、微博、知乎、Twitter、LinkedIn、GitHub）",
                    "- [x] 社交媒体账号（未激活，跳过）",
                ).replace(
                    "- [ ] 跨平台关联（用用户名/邮箱搜索其他平台，检查历史提交记录中的邮箱）",
                    "- [x] 跨平台关联（未激活，跳过）",
                )
                prompt += "\n\n" + recon_no_personnel

    if kb_context:
        prompt += "\n\n" + kb_context

    return prompt
