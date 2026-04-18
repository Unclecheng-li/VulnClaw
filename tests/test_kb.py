"""VulnClaw Knowledge Base Module Tests — store.py + retriever.py + updater.py"""

import json
import pytest
from pathlib import Path


# ── store.py ─────────────────────────────────────────────────────────

class TestKnowledgeStore:
    """Test KnowledgeStore."""

    def test_init_creates_dirs(self, tmp_path):
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        for category in ["cve", "techniques", "protocols", "tools", "payloads"]:
            assert (tmp_path / category).exists()

    def test_add_and_get_entry(self, tmp_path):
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        store.add_entry("cve", "CVE-2026-0001", {
            "title": "Test Vuln",
            "description": "A test vulnerability",
            "tags": ["test", "rce"],
        })
        entry = store.get_entry("cve", "CVE-2026-0001")
        assert entry is not None
        assert entry["title"] == "Test Vuln"
        assert entry["id"] == "CVE-2026-0001"

    def test_get_nonexistent_entry(self, tmp_path):
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        entry = store.get_entry("cve", "CVE-9999-9999")
        assert entry is None

    def test_search_by_title(self, tmp_path):
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        store.add_entry("cve", "CVE-2026-0001", {
            "title": "Nginx Buffer Overflow",
            "tags": ["nginx"],
        })
        results = store.search("nginx")
        assert len(results) >= 1
        assert results[0]["title"] == "Nginx Buffer Overflow"

    def test_search_by_tags(self, tmp_path):
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        store.add_entry("cve", "CVE-2026-0001", {
            "title": "Apache RCE",
            "tags": ["apache", "rce"],
        })
        results = store.search("apache", category="cve", tags=["apache"])
        assert len(results) >= 1

    def test_search_by_category(self, tmp_path):
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        store.add_entry("cve", "CVE-2026-0001", {"title": "CVE Test", "tags": []})
        store.add_entry("techniques", "sqli-bypass", {"title": "SQLi Bypass", "tags": ["sqli"]})
        results = store.search("test", category="cve")
        assert all(r.get("_category") == "cve" for r in results)

    def test_list_categories(self, tmp_path):
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        store.add_entry("cve", "CVE-2026-0001", {"title": "Test", "tags": []})
        store.add_entry("tools", "nmap", {"title": "Nmap", "tags": []})
        categories = store.list_categories()
        assert "cve" in categories
        assert "tools" in categories

    def test_list_entries(self, tmp_path):
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        store.add_entry("cve", "CVE-2026-0001", {"title": "Vuln 1", "tags": []})
        store.add_entry("cve", "CVE-2026-0002", {"title": "Vuln 2", "tags": []})
        entries = store.list_entries("cve")
        assert len(entries) == 2

    def test_get_stats(self, tmp_path):
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        store.add_entry("cve", "CVE-2026-0001", {"title": "Test", "tags": []})
        store.add_entry("tools", "nmap", {"title": "Nmap", "tags": []})
        stats = store.get_stats()
        assert "cve" in stats
        assert stats["cve"] >= 1

    def test_file_persistence(self, tmp_path):
        from vulnclaw.kb.store import KnowledgeStore
        store1 = KnowledgeStore(store_dir=tmp_path)
        store1.add_entry("cve", "CVE-2026-0001", {"title": "Persistent", "tags": []})
        # Create a new store loading from the same dir
        store2 = KnowledgeStore(store_dir=tmp_path)
        entry = store2.get_entry("cve", "CVE-2026-0001")
        assert entry is not None
        assert entry["title"] == "Persistent"

    def test_index_file_created(self, tmp_path):
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        store.add_entry("cve", "CVE-2026-0001", {"title": "Test", "tags": []})
        assert (tmp_path / "index.json").exists()


# ── retriever.py ─────────────────────────────────────────────────────

class TestKnowledgeRetriever:
    """Test KnowledgeRetriever."""

    def _make_retriever(self, tmp_path):
        from vulnclaw.kb.retriever import KnowledgeRetriever
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        return KnowledgeRetriever(store=store)

    def test_get_cve(self, tmp_path):
        from vulnclaw.kb.retriever import KnowledgeRetriever
        retriever = self._make_retriever(tmp_path)
        retriever.store.add_entry("cve", "CVE-2026-12345", {
            "title": "Test CVE",
            "description": "A test CVE entry",
            "tags": ["test"],
        })
        result = retriever.get_cve("CVE-2026-12345")
        assert result is not None
        assert result["title"] == "Test CVE"

    def test_get_cve_normalization(self, tmp_path):
        """CVE ID should be normalized (uppercase, prefixed)."""
        from vulnclaw.kb.retriever import KnowledgeRetriever
        retriever = self._make_retriever(tmp_path)
        retriever.store.add_entry("cve", "CVE-2026-12345", {
            "title": "Test CVE",
            "tags": ["test"],
        })
        result = retriever.get_cve("2026-12345")
        assert result is not None

    def test_search_by_service(self, tmp_path):
        from vulnclaw.kb.retriever import KnowledgeRetriever
        retriever = self._make_retriever(tmp_path)
        retriever.store.add_entry("cve", "CVE-2026-NGINX", {
            "title": "Nginx Vuln",
            "tags": ["nginx"],
        })
        results = retriever.search_by_service("nginx")
        assert len(results) >= 1

    def test_search_technique(self, tmp_path):
        from vulnclaw.kb.retriever import KnowledgeRetriever
        retriever = self._make_retriever(tmp_path)
        retriever.store.add_entry("techniques", "sqli-tech", {
            "title": "SQL Injection Techniques",
            "tags": ["sqli", "injection"],
        })
        results = retriever.search_technique("sqli")
        assert len(results) >= 1

    def test_get_waf_bypass(self, tmp_path):
        from vulnclaw.kb.retriever import KnowledgeRetriever
        retriever = self._make_retriever(tmp_path)
        retriever.store.add_entry("techniques", "waf-bypass-1", {
            "title": "WAF Bypass for SafeLine",
            "tags": ["waf-bypass", "safeline"],
        })
        results = retriever.get_waf_bypass("safeline")
        assert len(results) >= 1

    def test_get_tool_guide(self, tmp_path):
        from vulnclaw.kb.retriever import KnowledgeRetriever
        retriever = self._make_retriever(tmp_path)
        retriever.store.add_entry("tools", "nmap", {
            "title": "Nmap Usage Guide",
            "tags": ["scanner"],
        })
        result = retriever.get_tool_guide("nmap")
        assert result is not None

    def test_get_payload(self, tmp_path):
        from vulnclaw.kb.retriever import KnowledgeRetriever
        retriever = self._make_retriever(tmp_path)
        retriever.store.add_entry("payloads", "webshell-php", {
            "title": "PHP Webshell",
            "tags": ["webshell", "php"],
        })
        results = retriever.get_payload("webshell")
        assert len(results) >= 1

    def test_format_for_prompt(self, tmp_path):
        from vulnclaw.kb.retriever import KnowledgeRetriever
        retriever = self._make_retriever(tmp_path)
        entries = [
            {"title": "SQL Injection", "description": "A dangerous vuln"},
            {"title": "XSS", "description": "Cross-site scripting"},
        ]
        formatted = retriever.format_for_prompt(entries)
        assert "SQL Injection" in formatted
        assert "XSS" in formatted

    def test_format_for_prompt_empty(self, tmp_path):
        from vulnclaw.kb.retriever import KnowledgeRetriever
        retriever = self._make_retriever(tmp_path)
        formatted = retriever.format_for_prompt([])
        assert formatted == ""

    def test_format_for_prompt_max_entries(self, tmp_path):
        from vulnclaw.kb.retriever import KnowledgeRetriever
        retriever = self._make_retriever(tmp_path)
        entries = [{"title": f"Vuln {i}", "description": f"Desc {i}"} for i in range(10)]
        formatted = retriever.format_for_prompt(entries, max_entries=3)
        assert "Vuln 0" in formatted
        assert "Vuln 9" not in formatted


# ── updater.py ───────────────────────────────────────────────────────

class TestKnowledgeUpdater:
    """Test Knowledge seed/updater functionality."""

    def test_seed_knowledge_base(self, tmp_path):
        from vulnclaw.kb.updater import seed_knowledge_base
        from vulnclaw.kb.store import KnowledgeStore
        store = KnowledgeStore(store_dir=tmp_path)
        result = seed_knowledge_base(store)
        # Function returns None (in-place seeding), check store has data
        assert result is None or isinstance(result, int)
        # Check that the store has some data after seeding
        stats = store.get_stats()
        assert len(stats) > 0
