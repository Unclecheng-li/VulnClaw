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

- **高危发现**: {{ critical_count }} 个 Critical, {{ high_count }} 个 High
- **中低危发现**: {{ medium_count }} 个 Medium, {{ low_count }} 个 Low/Info
- **攻击面**: {{ attack_surface_summary }}

### 风险等级分布

| 等级 | 数量 |
|------|------|
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low/Info | {{ low_count }} |

### 关键建议

{% for rec in key_recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}

## 3. 详细发现

{% for finding in findings %}
### 3.{{ loop.index }} {{ finding.title }} — [{{ finding.severity }}]

- **漏洞类型**: {{ finding.vuln_type }}
- **CVE**: {{ finding.cve or "N/A" }}
- **影响范围**: {{ finding.description }}
- **验证步骤**:
{{ finding.evidence }}
- **PoC 脚本**: {% if finding.poc_script %}见附件 {{ finding.poc_script }}{% else %}N/A{% endif %}
- **修复建议**: {{ finding.remediation or "请根据漏洞类型采取相应修复措施" }}

{% endfor %}

## 4. 攻击路径

{% for step in executed_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

## 5. 附件

- PoC 脚本: 见 `pocs/` 目录
- 流量抓包: 见 `captures/` 目录
- 截图证据: 见 `screenshots/` 目录

---

> 🦞 报告由 VulnClaw 自动生成 | {{ generated_at }}
"""


def generate_report(
    session: SessionState,
    output_path: Optional[str] = None,
) -> Path:
    """Generate a penetration test report from session state.

    Args:
        session: Current session state with findings.
        output_path: Output file path. If None, auto-generate.

    Returns:
        Path to the generated report file.
    """
    from vulnclaw import __version__

    # Count findings by severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in session.findings:
        sev = finding.severity
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["Medium"] += 1

    # Generate key recommendations
    recommendations = []
    for finding in session.findings:
        if finding.severity in ("Critical", "High"):
            rec = finding.remediation or f"修复 {finding.vuln_type} 漏洞: {finding.title}"
            recommendations.append(rec)

    if not recommendations:
        recommendations.append("暂无高危发现，建议持续关注安全动态")

    # Build template context
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
        "findings": session.findings,
        "executed_steps": session.executed_steps,
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
    """Summarize the attack surface from recon data."""
    parts = []
    recon = session.recon_data

    if "ports" in recon:
        parts.append(f"开放端口: {recon['ports']}")
    if "services" in recon:
        parts.append(f"服务: {recon['services']}")
    if "technologies" in recon:
        parts.append(f"技术栈: {recon['technologies']}")
    if "waf" in recon:
        parts.append(f"WAF: {recon['waf']}")

    return "; ".join(parts) if parts else "未收集"
