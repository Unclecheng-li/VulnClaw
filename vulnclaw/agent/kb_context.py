"""Knowledge-base prompt context helpers for AgentCore."""

from __future__ import annotations

from typing import Any, Optional

from vulnclaw.kb.retriever import KnowledgeRetriever


def build_kb_context(agent, user_input: Optional[str] = None) -> str:
    """Build knowledge-base context for prompt injection."""
    if KnowledgeRetriever is None:
        return ""

    try:
        if agent._kb_retriever is None:
            agent._kb_retriever = KnowledgeRetriever()
    except Exception:
        return ""

    entries: list[dict[str, Any]] = []
    recon = getattr(agent.context.state, "recon_data", {})
    services = recon.get("services", [])
    for svc in services[:3]:
        parts = str(svc).lower().split("/")
        name = parts[0]
        version = parts[1] if len(parts) > 1 else ""
        entries.extend(agent._kb_retriever.search_by_service(name, version))

    for finding in agent.context.state.findings[:3]:
        vuln_type = (finding.vuln_type or "").lower()
        if vuln_type:
            entries.extend(agent._kb_retriever.search_technique(vuln_type))

    if user_input and "waf" in user_input.lower():
        entries.extend(agent._kb_retriever.get_waf_bypass())

    if user_input:
        for keyword in ("sqli", "xss", "rce", "lfi", "ssrf", "csrf", "deserialization"):
            if keyword in user_input.lower():
                entries.extend(agent._kb_retriever.search_technique(keyword))

    seen_ids: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for entry in entries:
        eid = entry.get("id", entry.get("title", ""))
        if eid and eid not in seen_ids:
            seen_ids.add(eid)
            deduped.append(entry)

    if not deduped:
        return ""

    formatted = agent._kb_retriever.format_for_prompt(deduped, max_entries=5)
    return (
        "## 知识库参考（相关 CVE / 利用技巧 / 绕过方法）\n"
        "以下信息来自本地安全知识库，供参考使用：\n\n"
        f"{formatted}\n"
    )
