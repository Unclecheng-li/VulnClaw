"""VulnClaw Knowledge Retriever — retrieve relevant knowledge for the agent."""

from __future__ import annotations

from typing import Any, Optional

from vulnclaw.kb.store import KnowledgeStore


class KnowledgeRetriever:
    """Retrieves relevant knowledge from the KB for the agent.

    Supports:
    - CVE-based retrieval
    - Service version-based CVE matching
    - Vulnerability type-based retrieval
    - WAF bypass technique retrieval
    """

    def __init__(self, store: Optional[KnowledgeStore] = None) -> None:
        self.store = store or KnowledgeStore()

    def get_cve(self, cve_id: str) -> Optional[dict[str, Any]]:
        """Get a specific CVE entry."""
        # Normalize CVE ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        return self.store.get_entry("cve", cve_id)

    def search_by_service(self, service: str, version: str = "") -> list[dict[str, Any]]:
        """Search CVEs by service name and version.

        Args:
            service: Service name, e.g. "nginx", "apache", "tomcat"
            version: Version string, e.g. "1.24.0"

        Returns:
            List of matching CVE entries.
        """
        query = service.lower()
        if version:
            query += f" {version}"

        return self.store.search(query, category="cve", tags=[service.lower()])

    def search_technique(self, vuln_type: str) -> list[dict[str, Any]]:
        """Search exploitation techniques by vulnerability type.

        Args:
            vuln_type: Vulnerability type, e.g. "sqli", "xss", "rce"

        Returns:
            List of matching technique entries.
        """
        return self.store.search(vuln_type.lower(), category="techniques")

    def get_waf_bypass(self, waf_name: str = "") -> list[dict[str, Any]]:
        """Get WAF bypass techniques.

        Args:
            waf_name: Specific WAF name, e.g. "safeline", "cloudflare"

        Returns:
            List of bypass technique entries.
        """
        if waf_name:
            return self.store.search(waf_name.lower(), category="techniques", tags=["waf-bypass"])
        return self.store.search("waf", category="techniques", tags=["waf-bypass"])

    def get_tool_guide(self, tool_name: str) -> Optional[dict[str, Any]]:
        """Get a tool usage guide."""
        return self.store.get_entry("tools", tool_name.lower())

    def get_payload(self, payload_type: str) -> list[dict[str, Any]]:
        """Get payloads by type.

        Args:
            payload_type: Type, e.g. "webshell", "reverse-shell", "encoding"

        Returns:
            List of payload entries.
        """
        return self.store.search(payload_type.lower(), category="payloads")

    def format_for_prompt(self, entries: list[dict[str, Any]], max_entries: int = 5) -> str:
        """Format knowledge entries for injection into LLM prompt.

        Args:
            entries: Knowledge entries to format.
            max_entries: Maximum number of entries to include.

        Returns:
            Formatted string for prompt injection.
        """
        if not entries:
            return ""

        lines = []
        for entry in entries[:max_entries]:
            title = entry.get("title", entry.get("id", "Unknown"))
            lines.append(f"- **{title}**")

            # Add description if available
            desc = entry.get("description", "")
            if desc:
                lines.append(f"  {desc[:200]}")

            # Add exploitation steps if available
            steps = entry.get("exploitation_steps", [])
            if steps:
                for i, step in enumerate(steps[:5], 1):
                    lines.append(f"  {i}. {step}")

        return "\n".join(lines)
