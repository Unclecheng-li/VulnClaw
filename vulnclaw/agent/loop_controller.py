"""Autonomous / persistent loop helpers for AgentCore."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Callable

from vulnclaw.agent.context import PentestPhase
from vulnclaw.agent.runtime_state import AgentResult, PersistentCycleResult

RECON_MIN_ROUNDS = 8



async def auto_pentest(
    agent: Any,
    user_input: str,
    target: str | None = None,
    max_rounds: int = 15,
    on_step: Callable[[int, AgentResult], None] | None = None,
) -> list[AgentResult]:
    results: list[AgentResult] = []

    detected_target = target or agent._detect_target(user_input)
    detected_phase = agent._detect_phase(user_input) or PentestPhase.RECON

    if detected_target:
        agent.context.state.target = detected_target
    if detected_phase:
        agent.context.state.advance_phase(detected_phase)

    agent.context.add_user_message(user_input)
    agent._reset_runtime_state(user_input=user_input, detected_phase=detected_phase)

    for round_num in range(1, max_rounds + 1):
        result = AgentResult()
        result.target = agent.context.state.target
        result.phase = agent.context.state.phase.value

        system_prompt = agent._build_system_prompt(
            agent.context.state.target,
            auto_mode=True,
            user_input=agent.runtime.auto_skill_input or user_input,
        )
        round_context = agent._build_round_context(round_num, max_rounds)

        try:
            response_text = await agent._call_llm_auto(system_prompt, round_context)
            result.output = response_text
            agent.context.add_assistant_message(f"[Round {round_num} 分析] {response_text}")
            agent._finding_parser.parse(response_text)

            if agent._is_recon_phase:
                agent._update_recon_dimension_completion(response_text)

            if agent._claimed_flag and not agent._flag_verified:
                verification_markers = [
                    "验证成功", "验证通过", "已验证", "复现成功", "确认flag",
                    "verified", "confirmed", "flag正确", "提交成功",
                    "flag 获取成功", "flag获取成功", "获取成功", "找到flag",
                    "flag found", "成功获取", "获取了flag", "拿到了flag",
                    "成功拿到", "成功找到", "解题完成", "解题成功",
                ]
                if any(m in response_text.lower() for m in verification_markers):
                    agent._flag_verified = True

            if agent._is_ctf_mode and agent._claimed_flag and not agent._flag_verified:
                flag_in_notes_count = sum(1 for note in agent.context.state.notes if agent._claimed_flag in note)
                if flag_in_notes_count >= 2:
                    agent._flag_verified = True
                elif flag_in_notes_count >= 1 and agent._claimed_flag in response_text:
                    agent._flag_verified = True

            new_phase = agent._detect_phase_from_output(response_text)
            if new_phase and new_phase != agent.context.state.phase:
                agent.context.state.advance_phase(new_phase)
                result.phase = new_phase.value

            result.should_continue = not agent._is_completion_signal(response_text)

            claimed_flag = agent._detect_flag_claim(response_text)
            if claimed_flag:
                if not agent._claimed_flag:
                    agent._claimed_flag = claimed_flag
                    agent._flag_verified = False
                    result.should_continue = True
                elif agent._claimed_flag == claimed_flag and not agent._flag_verified:
                    agent._flag_claim_count += 1
                    if agent._flag_claim_count >= 3:
                        agent._flag_verified = True
                    else:
                        result.should_continue = True

            if agent._is_ctf_mode and not result.should_continue:
                if not agent._flag_verified or not agent._claimed_flag:
                    result.should_continue = True

            if agent._is_recon_phase and not result.should_continue:
                if round_num < RECON_MIN_ROUNDS:
                    result.should_continue = True
                elif not agent.context.state.is_recon_complete():
                    result.should_continue = True

            if agent._flag_verified and agent._claimed_flag:
                agent._post_flag_rounds += 1
                if agent._post_flag_rounds >= 2:
                    result.should_continue = False

            step_raw = f"Round {round_num}: {response_text[:100]}..."
            sig = re.sub(r'Round\s*\d+:', '', step_raw).strip()[:60].lower()
            sig = re.sub(r'\s+', '_', sig)
            sig = re.sub(r'[^\w]', '', sig)

            if sig not in agent._seen_step_signatures:
                agent._seen_step_signatures.add(sig)
                agent.context.state.add_step(step_raw)

            agent._track_failed_target(response_text)

            current_findings = len(agent.context.state.findings)
            current_notes = len(agent.context.state.notes)
            current_steps = len(agent.context.state.executed_steps)

            is_spinning = False
            recent_notes = agent.context.state.notes[-5:]
            if recent_notes:
                all_words: list[str] = []
                for note in recent_notes:
                    all_words.extend(re.findall(r'[\u4e00-\u9fff]+', note))
                if all_words:
                    word_counts = Counter(all_words)
                    if word_counts.most_common(1)[0][1] >= 3:
                        is_spinning = True

            last_step = agent.context.state.executed_steps[-1] if agent.context.state.executed_steps else ""
            is_meaningful = agent._is_meaningful_step(last_step)

            has_new_progress = (
                current_findings > agent._last_findings_count
                or (current_notes > agent._last_notes_count and not is_spinning)
                or (current_steps > agent._last_steps_count + 1 and is_meaningful)
            )

            if has_new_progress:
                agent._rounds_without_progress = 0
                agent._python_timeout_rounds = 0
            else:
                agent._rounds_without_progress += 1

            agent._last_findings_count = current_findings
            agent._last_notes_count = current_notes
            agent._last_steps_count = current_steps

            if not has_new_progress and not agent._path_switch_forced:
                detected_path = agent._detect_attack_path(response_text)
                if detected_path:
                    if detected_path == agent._current_attack_path:
                        agent._same_path_fail_count += 1
                    else:
                        agent._current_attack_path = detected_path
                        agent._same_path_fail_count = 0
                        agent._path_switch_forced = False
            elif has_new_progress:
                agent._same_path_fail_count = 0
                agent._path_switch_forced = False

            agent.context.state.save()

        except Exception as e:
            result.output = f"[!] Round {round_num} 错误: {e}"
            agent._consecutive_errors += 1
            if agent._consecutive_errors >= 3:
                result.should_continue = False
            else:
                result.should_continue = True
                agent.context.trim_messages(max_messages=20)
        else:
            agent._consecutive_errors = 0

        results.append(result)
        if on_step:
            on_step(round_num, result)
        if not result.should_continue:
            break

    return results


async def persistent_pentest(
    agent: Any,
    user_input: str,
    target: str | None = None,
    rounds_per_cycle: int = 100,
    max_cycles: int = 10,
    auto_report: bool = True,
    on_cycle_step: Callable[[int, int, AgentResult], None] | None = None,
    on_cycle_complete: Callable[[int, PersistentCycleResult], None] | None = None,
) -> list[PersistentCycleResult]:
    cycle_results: list[PersistentCycleResult] = []

    detected_target = target or agent._detect_target(user_input)
    if detected_target:
        agent.context.state.target = detected_target

    agent.context.add_user_message(user_input)
    agent._reset_runtime_state(user_input=user_input)

    findings_at_cycle_start = len(agent.context.state.findings)
    cycle_num = 0
    should_stop = False

    while not should_stop:
        cycle_num += 1
        if max_cycles > 0 and cycle_num > max_cycles:
            should_stop = True
            break

        cycle_results_list: list[AgentResult] = []

        def _make_step_callback(cycle: int):
            def _on_step(round_num: int, result: AgentResult) -> None:
                cycle_results_list.append(result)
                if on_cycle_step:
                    on_cycle_step(round_num, cycle, result)
            return _on_step

        try:
            results = await agent.auto_pentest(
                user_input=(
                    f"[Persistent Cycle {cycle_num}] 继续对目标 {agent.context.state.target or '未知'} 进行渗透测试。"
                    f"这是第 {cycle_num} 个周期，保持之前的所有发现继续深入。"
                    if cycle_num > 1 else user_input
                ),
                target=agent.context.state.target,
                max_rounds=rounds_per_cycle,
                on_step=_make_step_callback(cycle_num),
            )
            cycle_results_list = results if results else cycle_results_list
        except KeyboardInterrupt:
            should_stop = True
            cycle_results_list = cycle_results_list or []

        total_findings = len(agent.context.state.findings)
        total_steps = len(agent.context.state.executed_steps)
        new_findings = total_findings - findings_at_cycle_start
        findings_at_cycle_start = total_findings

        llm_summary = ""
        try:
            llm_summary = await agent._generate_attack_summary()
        except Exception:
            pass

        report_path = None
        if auto_report:
            try:
                from vulnclaw.report.generator import generate_persistent_cycle_report

                report_path = generate_persistent_cycle_report(
                    session=agent.context.state,
                    cycle_num=cycle_num,
                    total_findings=total_findings,
                    new_findings=new_findings,
                    total_steps=total_steps,
                    rounds_per_cycle=rounds_per_cycle,
                    llm_attack_summary=llm_summary,
                )
            except Exception as e:
                report_path = f"报告生成失败: {e}"

        cycle_result = PersistentCycleResult(
            cycle_num=cycle_num,
            results=cycle_results_list,
            report_path=str(report_path) if report_path else None,
            total_findings=total_findings,
            total_steps=total_steps,
            stopped_early=should_stop,
        )
        cycle_results.append(cycle_result)

        if on_cycle_complete:
            on_cycle_complete(cycle_num, cycle_result)

        if cycle_results_list and not should_stop:
            last_result = cycle_results_list[-1]
            if not last_result.should_continue:
                if new_findings == 0 and total_findings > 0:
                    should_stop = True

    return cycle_results
