"""Prompt/round-context helpers for AgentCore."""

from __future__ import annotations

from typing import Any


def build_round_context(agent: Any, round_num: int, max_rounds: int) -> str:
    """Build context string for the current round in auto loop."""
    state = agent.context.state
    findings_summary = ""
    if state.findings:
        findings_summary = f"\n已发现漏洞: {len(state.findings)} 个"
        for finding in state.findings[-5:]:
            findings_summary += f"\n  - [{finding.severity}] {finding.title}: {finding.evidence[:100]}"

    user_hint_directive = ""
    if round_num <= agent.runtime.user_vuln_hint_rounds and agent.runtime.user_vuln_hint:
        user_hint_directive = (
            f"\n\n{'='*50}\n"
            f"【用户明确提示 — 第 {round_num}/{agent.runtime.user_vuln_hint_rounds} 轮】\n"
            f"{agent.runtime.user_vuln_hint}\n"
            f"{'='*50}\n"
        )
        agent.runtime.user_vuln_hint_rounds -= 1

    steps_summary = ""
    if state.executed_steps:
        recent_steps = state.executed_steps[-8:]
        steps_summary = f"\n最近执行步骤: {len(state.executed_steps)} 个总计"
        for step in recent_steps:
            steps_summary += f"\n  - {step[:150]}"

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
            for failure in failed_attempts[-10:]:
                failed_summary += f"\n  ❌ {failure}"

    recon_summary = ""
    if state.recon_data:
        recon_summary = f"\n侦察数据: {list(state.recon_data.keys())}"

    notes_summary = ""
    if state.notes:
        notes_summary = f"\n重要笔记: {'; '.join(state.notes[-5:])}"

    facts_summary = ""
    if hasattr(state, "confirmed_facts") and state.confirmed_facts:
        facts_summary = "\n已确认事实（工具验证过，可信）:"
        for fact in state.confirmed_facts[-8:]:
            facts_summary += f"\n  ✅ {fact[:150]}"

    assumptions_summary = ""
    if hasattr(state, "unverified_assumptions") and state.unverified_assumptions:
        assumptions_summary = "\n⚠️ 未验证假设（推理基础但未确认，可能错误）:"
        for assumption in state.unverified_assumptions[-5:]:
            assumptions_summary += f"\n  ❓ {assumption[:150]}"
        assumptions_summary += "\n→ 如果某条假设是错的，基于它的推理全部作废！优先验证关键假设。"

    path_warning = ""
    same_path_fails = agent.runtime.same_path_fail_count

    if state.executed_steps:
        recent = state.executed_steps[-8:]
        if len(recent) >= 5:
            recent_text = " ".join(recent).lower()
            stuck_indicators = ["get=", "post=", "payload", "参数", "尝试"]
            stuck_count = sum(1 for indicator in stuck_indicators if recent_text.count(indicator) >= 3)
            if stuck_count >= 1:
                path_warning = (
                    "\n\n⚠️ 你已经在当前路径上尝试了多轮但没有突破。"
                    "\n请重新审视源码/信息，是否有其他更简单的利用路径？"
                    "\n列出所有可能的路径，然后切换到最简单的一条。"
                )

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
        agent.runtime.same_path_fail_count = 0
        agent.runtime.path_switch_forced = True

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

    python_timeout_warning = ""
    python_timeout_rounds = agent.runtime.python_timeout_rounds
    if python_timeout_rounds >= 1:
        python_timeout_warning = (
            "\n\n⚠️ **代码执行警告**：上轮 Python 脚本超时了。"
            "\n禁止写超过 10 行的复杂脚本。"
            "\n优先使用已有的工具（fetch/python_execute）而非自己写爬虫/解析代码。"
            "\n禁止重复执行相同的大段脚本。"
        )

    dead_loop_warning = ""
    rounds_no_progress = agent.runtime.rounds_without_progress
    stale_threshold = agent.config.session.stale_rounds_threshold

    blocked_targets_warning = ""
    blocked_targets = agent.runtime.blocked_targets
    if blocked_targets:
        blocked_targets_warning = (
            f"\n\n🚨 **目标不可访问警告**：以下目标已连续多次访问失败，禁止再次尝试："
            f"\n{chr(10).join(f'  ❌ {target} — 已确认不可达' for target in blocked_targets)}"
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

    flag_warning = ""
    claimed_flag = agent.runtime.claimed_flag
    flag_verified = agent.runtime.flag_verified
    if claimed_flag and flag_verified:
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

    ctf_mode_warning = ""
    is_ctf = agent.runtime.is_ctf_mode
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

    recon_dim_status = ""
    if agent.runtime.is_recon_phase:
        dim_status_text = state.get_recon_status_text()
        is_complete = state.is_recon_complete()
        rounds_no_progress = agent.runtime.rounds_without_progress

        recon_dim_status = f"\n\n📊 信息收集维度完成度:\n{dim_status_text}"
        if not is_complete:
            recon_dim_status += (
                "\n\n🔴 信息收集未完成！还有维度未检查，禁止标记 [DONE]。"
                "\n请继续对未完成的维度执行检查，确保每个维度都至少做过一轮。"
            )
        elif (is_complete and rounds_no_progress >= 3) or (rounds_no_progress >= 8 + 5):
            output_dir = str(agent.config.session.output_dir.resolve())
            if is_complete:
                trigger_reason = f"所有维度均已完成 ✅，连续 {rounds_no_progress} 轮无新进展"
            else:
                trigger_reason = f"连续 {rounds_no_progress} 轮无新进展（8+5 安全阀）"
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
        if round_num < 8:
            recon_dim_status += (
                f"\n\n🔴 信息收集最低轮数保障：当前第 {round_num} 轮，"
                f"最低需 8 轮。即使觉得够了也请继续深入。"
            )

    return (
        f"\n\n[自主循环 Round {round_num}/{max_rounds}]"
        f"\n当前目标: {state.target or '未设置'}"
        f"\n当前阶段: {state.phase.value}"
        f"\n输出目录: {agent.config.session.output_dir.resolve()}"
        f"{user_hint_directive}"
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


async def generate_attack_summary(agent: Any) -> str:
    """Generate a detailed attack path summary for the cycle report."""
    state = agent.context.state

    steps = state.executed_steps[-30:] if state.executed_steps else []
    steps_text = "\n".join(f"{i+1}. {step}" for i, step in enumerate(steps)) if steps else "（无步骤记录）"

    notes = state.notes[-20:] if state.notes else []
    notes_text = "\n".join(f"- {note}" for note in notes) if notes else "（无观察记录）"

    findings = state.findings
    if findings:
        lines = []
        for finding in findings:
            evidence = (finding.evidence or "")[:150].strip()
            lines.append(f"[{finding.severity}] {finding.title} | 证据: {evidence or '无'}")
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
        f"4. 漏洞与攻击面的关联（如通过目录枚举发现 /manager/html，命中 CVE-2023-44487）\n"
        f"5. 子域名发现情况（如发现 api.target.com、cms.target.com 等）\n"
        f"格式要求：用自然段落叙事，不用列表，长度 200-400 字，纯中文，不含 <thinking> 标签。"
    )

    try:
        client = agent._get_client()
        messages = [{"role": "user", "content": prompt}]
        response = client.chat.completions.create(
            model=agent.config.llm.model,
            messages=messages,
            max_tokens=800,
            temperature=0.3,
        )
        if response and response.choices:
            raw = response.choices[0].message.content or ""
            from vulnclaw.agent.think_filter import strip_think_tags

            return strip_think_tags(raw).strip()
    except Exception:
        pass
    return ""
