"""VulnClaw Report Generator — generate structured penetration test reports."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from jinja2 import Template

from vulnclaw.agent.context import SessionState, VulnerabilityFinding


# ── Report Template ─────────────────────────────────────────────────

REPORT_TEMPLATE = """\
# 渗透测试报告

## 1. 项目概述

| 项目 | 详情 |
|------|------|
| **测试目标** | {{ target }} |
| **测试时间** | {{ started_at }} |
| **报告生成** | {{ generated_at }} |
| **测试工具** | VulnClaw v{{ version }} |

## 2. 执行摘要

{% if verified_count > 0 %}
- **已验证漏洞**: {{ verified_count }} 个（其中高危 {{ critical_count }} 个 Critical, {{ high_count }} 个 High）
{% else %}
- **已验证漏洞**: 0 个
{% endif %}
- **误报排除**: {{ rejected_count }} 个
- **待验证**: {{ pending_count }} 个（未在报告中显示）
- **攻击面**: {{ attack_surface_summary }}

{% if rejected_count > 0 %}
### 已排除的误报

以下漏洞假设经 PoC 验证失败，已排除，不计入报告：

{% for f in rejected_findings %}
- {{ f.title }} — {{ f.verification_note }}
{% endfor %}
{% endif %}

### 风险等级分布

| 等级 | 数量 |
|------|------|
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low/Info | {{ low_count }} |

{% if verified_findings %}
### 关键建议

{% for rec in key_recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
{% else %}
### 漏洞发现

**本次测试未发现有效漏洞。**

可能原因：
- 目标系统安全配置较好
- 渗透深度不够（信息收集轮数不足）
- 漏洞利用条件未满足

建议：
- 增加渗透测试轮数
- 尝试更多漏洞类型
- 检查是否需要特殊认证或访问权限
{% endif %}

## 3. 详细发现

{% for finding in findings %}
### 3.{{ loop.index }} {{ finding.title }} — [{{ finding.severity }}]
{% if finding.verification_status == "pending" %}
> ⚠️ **待验证** — 此漏洞由自动检测发现，尚未通过 PoC 验证。请手动审查。
{% elif finding.verification_status == "rejected" %}
> ❌ **已排除（误报）** — {{ finding.verification_note or "经验证为误报" }}
{% endif %}

- **漏洞类型**: {{ finding.vuln_type or "未分类" }}
- **CVE**: {{ finding.cve or "N/A" }}
- **影响范围**: {{ finding.description or "无" }}
{% if finding.evidence %}
- **验证证据**: {{ finding.evidence }}
{% endif %}
{% if finding.poc_script %}
- **PoC 脚本**: 见附件 `{{ finding.poc_script }}`
{% endif %}
- **修复建议**: {{ finding.remediation or "请根据漏洞类型采取相应修复措施" }}
{% if finding.verified and finding.verified_at %}
- **验证时间**: {{ finding.verified_at }}
{% endif %}

{% endfor %}

{% if llm_attack_summary %}
## 4. 攻击路径摘要

{{ llm_attack_summary }}

{% elif step_summary and step_summary.total_steps > 0 %}
## 4. 攻击路径摘要

{% for phase_name, phase_data in step_summary.phases.items() %}
### {{ phase_name }}（共 {{ phase_data.count }} 步）

| 状态 | 数量 |
|------|------|
| ✅ 成功 | {{ phase_data.success_count }} |
| ❌ 失败 | {{ phase_data.failure_count }} |

**关键动作**: {{ phase_data.actions[:5]|join(', ') }}

{% if phase_data.key_results %}
**主要发现**:
{% for result in phase_data.key_results %}
- {{ result }}
{% endfor %}
{% endif %}

---
{% endfor %}

**总计**: {{ step_summary.total_steps }} 步

{% if step_summary.key_findings %}
### 关键发现时间线

{% for finding in step_summary.key_findings %}
- {{ finding }}
{% endfor %}
{% endif %}

{% elif findings %}
## 4. 攻击路径

{% for step in executed_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

## 5. 附件

- PoC 脚本: 见 `pocs/` 目录
- 流量抓包: 见 `captures/` 目录
- 截图证据: 见 `screenshots/` 目录

---

> 🦞 报告由 VulnClaw 自动生成 | {{ generated_at }}
> **原则**: 未经验证的漏洞 = 误报 = 不写入报告
"""


def generate_report(
    session: SessionState,
    output_path: Optional[str] = None,
    llm_attack_summary: str = "",  # ★ LLM 生成的攻击路径摘要
    report_format: str = "markdown",
) -> Path:
    """Generate a penetration test report from session state.

    只包含已验证 (verified=True) 的漏洞。未验证的漏洞不会写入报告。

    Args:
        session: Current session state with findings.
        output_path: Output file path. If None, auto-generate.

    Returns:
        Path to the generated report file.
    """
    from vulnclaw import __version__

    # ★ 包含所有 findings（包括 pending 和 confirmed，不只是 verified）
    all_findings = session.findings
    verified_findings = session.get_verified_findings()
    pending_findings = session.get_pending_findings()
    rejected_findings = session.get_rejected_findings()

    # Count verified findings by severity (only verified count toward real results)
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in verified_findings:
        sev = finding.severity
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["Medium"] += 1

    # Generate recommendations from verified high/critical findings only
    # Deduplicate by vuln_type: only one recommendation per vulnerability type
    seen_vuln_types = set()
    recommendations = []
    for finding in verified_findings:
        if finding.severity in ("Critical", "High"):
            vt = finding.vuln_type or "未分类"
            if vt in seen_vuln_types:
                continue  # Already have a rec for this vuln_type
            seen_vuln_types.add(vt)
            rec = finding.remediation or f"修复 {vt} 漏洞: {finding.title}"
            recommendations.append(rec)

    if not recommendations:
        recommendations.append("暂无高危发现，建议持续关注安全动态")

    # Build template context
    # ★ 攻击路径摘要（过滤 LLM 原始输出中的 think 标签 / 调试标记）
    from vulnclaw.report.filter import ReportContentFilter
    filtered_summary = ReportContentFilter.filter(llm_attack_summary) if llm_attack_summary else ""
    context = {
        "target": session.target or "未指定",
        "started_at": session.started_at,
        "generated_at": datetime.now().isoformat(),
        "version": __version__,
        "critical_count": severity_counts["Critical"],
        "high_count": severity_counts["High"],
        "medium_count": severity_counts["Medium"],
        "low_count": severity_counts["Low"] + severity_counts["Info"],
        "attack_surface_summary": _summarize_attack_surface(session),
        "key_recommendations": recommendations,
        "findings": verified_findings,  # ★ 只包含已验证漏洞，pending/rejected 不写入详细发现章节
        "executed_steps": session.executed_steps,
        # ★ 额外统计信息
        "total_findings_submitted": len(all_findings),
        "verified_count": len(verified_findings),
        "rejected_count": len(rejected_findings),
        "pending_count": len(pending_findings),
        "rejected_findings": rejected_findings,
        "step_summary": session.get_step_summary(),
        "llm_attack_summary": filtered_summary,
    }

    # Render report
    template = Template(REPORT_TEMPLATE)
    report_content = template.render(**context)

    # Determine output path
    if output_path is None:
        from vulnclaw.config.settings import SESSIONS_DIR
        safe_target = (session.target or "unknown").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(SESSIONS_DIR / f"report_{timestamp}_{safe_target}.md")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if report_format.lower() == "html":
        html_content = Template(
            """<!doctype html><html><head><meta charset="utf-8"><title>VulnClaw Report</title></head><body><pre>{{ content }}</pre></body></html>"""
        ).render(content=report_content)
        output = output.with_suffix(".html") if output.suffix.lower() != ".html" else output
        output.write_text(html_content, encoding="utf-8")
    else:
        output.write_text(report_content, encoding="utf-8")

    # Also generate PoC scripts
    from vulnclaw.report.poc_builder import generate_pocs
    pocs_dir = output.parent / "pocs"
    generate_pocs(session, pocs_dir)

    return output


def generate_report_from_file(session_path: str) -> Path:
    """Generate a report from a saved session JSON file."""
    session = SessionState.load(Path(session_path))
    return generate_report(session)


def _summarize_attack_surface(session: SessionState) -> str:
    """Summarize the attack surface from recon data, including subdomains."""
    parts = []
    recon = session.recon_data

    if "subdomains" in recon and recon["subdomains"]:
        parts.append(f"子域名: {', '.join(recon['subdomains'][:10])}")
    if "ports" in recon:
        parts.append(f"开放端口: {recon['ports']}")
    if "services" in recon:
        parts.append(f"服务: {recon['services']}")
    if "technologies" in recon:
        parts.append(f"技术栈: {recon['technologies']}")
    if "waf" in recon:
        parts.append(f"WAF: {recon['waf']}")
    if "domains" in recon:
        parts.append(f"关联域名: {', '.join(recon['domains'][:5])}")

    return "; ".join(parts) if parts else "未收集"


# ── Persistent Pentest Cycle Report ──────────────────────────────────

CYCLE_REPORT_TEMPLATE = """\
# 持续性渗透测试 — 周期报告

## 周期信息

| 项目 | 详情 |
|------|------|
| **测试目标** | {{ target }} |
| **当前周期** | 第 {{ cycle_num }} 周期 |
| **每周期轮数** | {{ rounds_per_cycle }} |
| **本周期新增已验证漏洞** | {{ new_findings }} 个 |
| **累计已验证漏洞** | {{ total_findings }} 个 |
| **累计执行步骤** | {{ total_steps }} 个 |
| **报告生成时间** | {{ generated_at }} |

{% if cycle_findings %}
## 本周期漏洞发现

{% for finding in cycle_findings %}
### {{ loop.index }}. {{ finding.title }} — [{{ finding.severity }}]
{% if finding.verification_status == "pending" %}
> ⚠️ **待验证** — 此漏洞由自动检测发现，尚未通过 PoC 验证。
{% endif %}
- **漏洞类型**: {{ finding.vuln_type or "未分类" }}
- **CVE**: {{ finding.cve or "N/A" }}
- **影响范围**: {{ finding.description or "无" }}
{% if finding.evidence %}
- **验证证据**: {{ finding.evidence }}
{% endif %}
- **修复建议**: {{ finding.remediation or "请根据漏洞类型采取相应修复措施" }}
{% if finding.verified_at %}
- **验证时间**: {{ finding.verified_at }}
{% endif %}

{% endfor %}
{% else %}
## 本周期漏洞发现

本周期未发现新漏洞。
{% endif %}

## 累计漏洞汇总

| # | 漏洞标题 | 等级 | 类型 | 证据/URL | 状态 |
|---|---------|------|------|---------|------|
{% for finding in all_findings %}
{% set ev = (finding.evidence or finding.description or "")[:80] %}
| {{ loop.index }} | {{ finding.title }} | {{ finding.severity }} | {{ finding.vuln_type or "—" }} | {{ ev if ev else "—" }} | {% if finding.verification_status == "verified" %}✅ 已验证{% elif finding.verification_status == "pending" %}⚠️ 待验证{% else %}❌ 已排除{% endif %} |
{% endfor %}

{% if not all_findings %}
暂未发现漏洞
{% endif %}

## 风险等级分布

| 等级 | 数量 |
|------|------|
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low/Info | {{ low_count }} |

{% if llm_attack_summary %}
## 攻击路径摘要

{{ llm_attack_summary }}

{% elif step_summary and step_summary.total_steps > 0 %}
## 攻击路径摘要

{% for phase_name, phase_data in step_summary.phases.items() %}
### {{ phase_name }}（共 {{ phase_data.count }} 步）

| 状态 | 数量 |
|------|------|
| ✅ 成功 | {{ phase_data.success_count }} |
| ❌ 失败 | {{ phase_data.failure_count }} |

**关键动作**: {{ phase_data.actions[:5]|join(', ') }}

{% if phase_data.key_results %}
**主要发现**:
{% for result in phase_data.key_results %}
- {{ result }}
{% endfor %}
{% endif %}

---
{% endfor %}

**总计**: {{ step_summary.total_steps }} 步

{% if step_summary.key_findings %}
### 关键发现时间线

{% for finding in step_summary.key_findings %}
- {{ finding }}
{% endfor %}
{% endif %}

{% elif recent_steps %}
## 攻击路径摘要

{% for step in recent_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

## 关键建议

{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}

---

> 🦞 持续性渗透测试周期报告 | VulnClaw | {{ generated_at }}
> **原则**: 未经验证的漏洞 = 误报 = 不写入报告
"""


def generate_persistent_cycle_report(
    session: SessionState,
    cycle_num: int,
    total_findings: int,
    new_findings: int,
    total_steps: int,
    rounds_per_cycle: int,
    output_path: Optional[str] = None,
    llm_attack_summary: str = "",  # ★ LLM 生成的攻击路径摘要
) -> Path:
    """Generate a cycle report for persistent pentest.

    只包含已验证 (verified=True) 的漏洞。

    Args:
        session: Current session state with findings.
        cycle_num: Current cycle number (1-based).
        total_findings: Total findings so far (cumulative).
        new_findings: New findings in this cycle.
        total_steps: Total executed steps so far (cumulative).
        rounds_per_cycle: Rounds per cycle.
        output_path: Output file path. If None, auto-generate.

    Returns:
        Path to the generated report file.
    """
    from vulnclaw import __version__

    # ★ 包含所有 findings（包括 pending 和 confirmed，不只是 verified）
    all_findings = session.findings
    verified_findings = session.get_verified_findings()

    # Count verified findings by severity only (pending doesn't count as real result)
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in verified_findings:
        sev = finding.severity
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["Medium"] += 1

    # ★ 本周期新增已验证 findings（只统计 verified）
    cycle_findings = verified_findings[-new_findings:] if new_findings > 0 else []

    # Generate recommendations from verified high/critical findings only
    # Deduplicate by vuln_type: only one recommendation per vulnerability type
    seen_vuln_types = set()
    recommendations = []
    for finding in verified_findings:
        if finding.severity in ("Critical", "High"):
            vt = finding.vuln_type or "未分类"
            if vt in seen_vuln_types:
                continue
            seen_vuln_types.add(vt)
            rec = finding.remediation or f"修复 {vt} 漏洞: {finding.title}"
            recommendations.append(rec)
    if not recommendations:
        recommendations.append("暂无高危发现，继续深入测试")

    # Recent steps (last 20 to avoid bloat)
    recent_steps = session.executed_steps[-20:]

    # ★ 攻击路径摘要（过滤 LLM 原始输出中的 think 标签 / 调试标记）
    step_summary = session.get_step_summary()
    from vulnclaw.report.filter import ReportContentFilter
    filtered_summary = ReportContentFilter.filter(llm_attack_summary) if llm_attack_summary else ""

    context = {
        "target": session.target or "未指定",
        "cycle_num": cycle_num,
        "rounds_per_cycle": rounds_per_cycle,
        "new_findings": len(cycle_findings),
        "total_findings": len(all_findings),
        "total_steps": total_steps,
        "generated_at": datetime.now().isoformat(),
        "version": __version__,
        "cycle_findings": cycle_findings,
        "all_findings": all_findings,  # ★ 包含所有 findings（包括 pending）
        "critical_count": severity_counts["Critical"],
        "high_count": severity_counts["High"],
        "medium_count": severity_counts["Medium"],
        "low_count": severity_counts["Low"] + severity_counts["Info"],
        "recent_steps": recent_steps,
        "recommendations": recommendations,
        "step_summary": step_summary,
        "llm_attack_summary": filtered_summary,
    }

    # Render report
    template = Template(CYCLE_REPORT_TEMPLATE)
    report_content = template.render(**context)

    # Determine output path
    if output_path is None:
        from vulnclaw.config.settings import SESSIONS_DIR
        safe_target = (session.target or "unknown").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(
            SESSIONS_DIR / f"persistent_cycle{cycle_num:03d}_{timestamp}_{safe_target}.md"
        )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report_content, encoding="utf-8")

    return output
