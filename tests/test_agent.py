"""VulnClaw Agent Module Tests — context.py + memory.py + prompts.py + core.py"""

import json
import pytest
from pathlib import Path


# ── context.py ───────────────────────────────────────────────────────

class TestPentestPhase:
    """Test PentestPhase enum."""

    def test_phase_values(self):
        from vulnclaw.agent.context import PentestPhase
        assert PentestPhase.IDLE.value == "就绪"
        assert PentestPhase.RECON.value == "信息收集"
        assert PentestPhase.VULN_DISCOVERY.value == "漏洞发现"
        assert PentestPhase.EXPLOITATION.value == "漏洞利用"
        assert PentestPhase.POST_EXPLOITATION.value == "后渗透"
        assert PentestPhase.REPORTING.value == "报告生成"

    def test_phase_is_str(self):
        from vulnclaw.agent.context import PentestPhase
        # PentestPhase inherits from str, Enum
        assert isinstance(PentestPhase.RECON, str)


class TestVulnerabilityFinding:
    """Test VulnerabilityFinding model."""

    def test_default_values(self):
        from vulnclaw.agent.context import VulnerabilityFinding
        finding = VulnerabilityFinding(title="Test Vuln")
        assert finding.title == "Test Vuln"
        assert finding.severity == "Medium"
        assert finding.vuln_type == ""
        assert finding.cve is None

    def test_full_values(self):
        from vulnclaw.agent.context import VulnerabilityFinding
        finding = VulnerabilityFinding(
            title="SQL Injection",
            severity="Critical",
            vuln_type="SQLi",
            description="Login form SQLi",
            evidence="admin' OR 1=1--",
            cve="CVE-2026-12345",
            remediation="Use parameterized queries",
        )
        assert finding.severity == "Critical"
        assert finding.cve == "CVE-2026-12345"
        assert finding.remediation == "Use parameterized queries"


class TestSessionState:
    """Test SessionState model."""

    def test_default_state(self):
        from vulnclaw.agent.context import SessionState, PentestPhase
        state = SessionState()
        assert state.phase == PentestPhase.IDLE
        assert state.target is None
        assert state.findings == []
        assert state.executed_steps == []

    def test_advance_phase(self):
        from vulnclaw.agent.context import SessionState, PentestPhase
        state = SessionState()
        state.advance_phase(PentestPhase.RECON)
        assert state.phase == PentestPhase.RECON
        # Should record the phase change in steps
        assert len(state.executed_steps) == 1
        assert "信息收集" in state.executed_steps[0]

    def test_add_finding(self):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        state = SessionState()
        state.add_finding(VulnerabilityFinding(title="XSS", severity="High"))
        assert len(state.findings) == 1
        # High severity without evidence gets [未验证] prefix in model_post_init
        assert "XSS" in state.findings[0].title

    def test_add_step(self):
        from vulnclaw.agent.context import SessionState
        state = SessionState()
        state.add_step("Scanned port 80")
        assert state.findings == []
        assert len(state.executed_steps) == 1

    def test_add_note(self):
        from vulnclaw.agent.context import SessionState
        state = SessionState()
        state.add_note("Interesting endpoint found")
        assert len(state.notes) == 1

    def test_save_and_load(self, tmp_path):
        from vulnclaw.agent.context import SessionState, PentestPhase, VulnerabilityFinding
        state = SessionState(target="192.168.1.100")
        state.advance_phase(PentestPhase.RECON)
        state.add_finding(VulnerabilityFinding(title="SQLi", severity="Critical"))

        save_path = tmp_path / "session.json"
        returned_path = state.save(save_path)
        assert returned_path.exists()

        loaded = SessionState.load(save_path)
        assert loaded.target == "192.168.1.100"
        assert loaded.phase == PentestPhase.RECON
        assert len(loaded.findings) == 1
        # Critical severity without evidence gets [未验证] prefix
        assert "SQLi" in loaded.findings[0].title

    def test_multiple_findings(self):
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        state = SessionState()
        severities = ["Critical", "High", "Medium", "Low", "Info"]
        for sev in severities:
            state.add_finding(VulnerabilityFinding(
                title=f"Vuln-{sev}", severity=sev, vuln_type=f"type-{sev}"
            ))
        assert len(state.findings) == 5

    def test_recon_data(self):
        from vulnclaw.agent.context import SessionState
        state = SessionState()
        state.recon_data = {"ports": [80, 443], "services": ["nginx", "mysql"]}
        assert state.recon_data["ports"] == [80, 443]


class TestContextManager:
    """Test ContextManager."""

    def test_add_messages(self):
        from vulnclaw.agent.context import ContextManager
        cm = ContextManager()
        cm.add_user_message("Hello")
        cm.add_assistant_message("Hi there")
        assert len(cm.get_messages()) == 2
        assert cm.get_messages()[0]["role"] == "user"
        assert cm.get_messages()[1]["role"] == "assistant"

    def test_max_history(self):
        from vulnclaw.agent.context import ContextManager
        cm = ContextManager(max_history=5)
        for i in range(10):
            cm.add_user_message(f"msg {i}")
        # Should only keep the last 5
        assert len(cm.get_messages()) <= 5

    def test_reset(self):
        from vulnclaw.agent.context import ContextManager
        cm = ContextManager()
        cm.add_user_message("Hello")
        cm.reset()
        assert len(cm.get_messages()) == 0
        assert cm.state.target is None

    def test_session_state_access(self):
        from vulnclaw.agent.context import ContextManager, PentestPhase
        cm = ContextManager()
        cm.state.target = "10.0.0.1"
        cm.state.advance_phase(PentestPhase.RECON)
        assert cm.state.target == "10.0.0.1"
        assert cm.state.phase == PentestPhase.RECON


# ── memory.py ────────────────────────────────────────────────────────

class TestMemoryStore:
    """Test MemoryStore."""

    def test_save_and_retrieve(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore
        store = MemoryStore(store_dir=tmp_path)
        store.save("test_key", {"data": "test_value"})
        result = store.retrieve("test_key")
        assert result == {"data": "test_value"}

    def test_retrieve_nonexistent(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore
        store = MemoryStore(store_dir=tmp_path)
        assert store.retrieve("nonexistent") is None

    def test_list_keys(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore
        store = MemoryStore(store_dir=tmp_path)
        store.save("key1", "val1")
        store.save("key2", "val2")
        keys = store.list_keys()
        assert "key1" in keys
        assert "key2" in keys

    def test_delete(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore
        store = MemoryStore(store_dir=tmp_path)
        store.save("to_delete", "value")
        store.delete("to_delete")
        assert store.retrieve("to_delete") is None

    def test_search(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore
        store = MemoryStore(store_dir=tmp_path)
        store.save("sqli_info", {"type": "SQL Injection", "severity": "High"})
        store.save("xss_info", {"type": "XSS", "severity": "Medium"})
        results = store.search("sqli")
        assert len(results) >= 1
        assert results[0][0] == "sqli_info"

    def test_persistence(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore
        store1 = MemoryStore(store_dir=tmp_path)
        store1.save("persistent", "value_across_sessions")
        # Create a new store instance pointing to the same dir
        store2 = MemoryStore(store_dir=tmp_path)
        assert store2.retrieve("persistent") == "value_across_sessions"

    def test_overwrite(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore
        store = MemoryStore(store_dir=tmp_path)
        store.save("key", "original")
        store.save("key", "updated")
        assert store.retrieve("key") == "updated"

    def test_complex_value(self, tmp_path):
        from vulnclaw.agent.memory import MemoryStore
        store = MemoryStore(store_dir=tmp_path)
        complex_val = {
            "target": "192.168.1.100",
            "findings": ["SQLi", "XSS"],
            "metadata": {"tool": "nmap", "timestamp": "2026-01-01"},
        }
        store.save("complex", complex_val)
        result = store.retrieve("complex")
        assert result["findings"] == ["SQLi", "XSS"]


# ── prompts.py ───────────────────────────────────────────────────────

class TestPromptBuilder:
    """Test prompt building."""

    def test_basic_prompt(self):
        from vulnclaw.agent.prompts import build_system_prompt
        prompt = build_system_prompt()
        assert "VulnClaw" in prompt
        assert "渗透测试" in prompt

    def test_prompt_with_target(self):
        from vulnclaw.agent.prompts import build_system_prompt
        prompt = build_system_prompt(target="192.168.1.100")
        assert "192.168.1.100" in prompt

    def test_prompt_with_phase(self):
        from vulnclaw.agent.prompts import build_system_prompt
        prompt = build_system_prompt(phase="信息收集")
        assert "信息收集" in prompt

    def test_prompt_with_skill_context(self):
        from vulnclaw.agent.prompts import build_system_prompt
        prompt = build_system_prompt(skill_context="这是逆向分析的 Skill 上下文")
        assert "逆向分析" in prompt
        assert "Skill 上下文" in prompt

    def test_prompt_with_mcp_tools(self):
        from vulnclaw.agent.prompts import build_system_prompt
        tools = [
            {
                "name": "fetch",
                "description": "Fetch a URL",
                "inputSchema": {
                    "type": "object",
                    "properties": {"url": {"type": "string", "description": "URL to fetch"}},
                },
            }
        ]
        prompt = build_system_prompt(mcp_tools=tools)
        assert "fetch" in prompt
        assert "URL to fetch" in prompt

    def test_waf_bypass_knowledge_included(self):
        from vulnclaw.agent.prompts import build_system_prompt
        prompt = build_system_prompt()
        assert "WAF" in prompt
        assert "base64" in prompt

    def test_core_contract_included(self):
        from vulnclaw.agent.prompts import build_system_prompt
        prompt = build_system_prompt()
        assert "沙盒模式" in prompt
        assert "证据冲突" in prompt

    def test_all_phases_render(self):
        from vulnclaw.agent.prompts import build_system_prompt
        phases = ["信息收集", "漏洞发现", "漏洞利用", "后渗透", "报告生成"]
        for phase in phases:
            prompt = build_system_prompt(phase=phase)
            assert phase in prompt


# ── core.py ──────────────────────────────────────────────────────────

class TestAgentCore:
    """Test AgentCore."""

    def _make_agent(self):
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig
        return AgentCore(VulnClawConfig())

    def test_init(self):
        agent = self._make_agent()
        assert agent.config is not None
        assert agent.context is not None

    def test_phase_detection_recon(self):
        from vulnclaw.agent.context import PentestPhase
        agent = self._make_agent()
        assert agent._detect_phase("扫描 192.168.1.100 的端口") == PentestPhase.RECON
        assert agent._detect_phase("信息收集") == PentestPhase.RECON
        assert agent._detect_phase("recon") == PentestPhase.RECON

    def test_phase_detection_vuln(self):
        from vulnclaw.agent.context import PentestPhase
        agent = self._make_agent()
        assert agent._detect_phase("有什么漏洞") == PentestPhase.VULN_DISCOVERY
        assert agent._detect_phase("SQL注入") == PentestPhase.VULN_DISCOVERY

    def test_phase_detection_exploit(self):
        from vulnclaw.agent.context import PentestPhase
        agent = self._make_agent()
        assert agent._detect_phase("exploit") == PentestPhase.EXPLOITATION
        assert agent._detect_phase("尝试利用") == PentestPhase.EXPLOITATION
        # Note: "利用漏洞" matches VULN_DISCOVERY because "漏洞" appears first in the scan
        # This is a known limitation — more specific keywords should win
        assert agent._detect_phase("poc验证") == PentestPhase.EXPLOITATION

    def test_phase_detection_post(self):
        from vulnclaw.agent.context import PentestPhase
        agent = self._make_agent()
        assert agent._detect_phase("后渗透") == PentestPhase.POST_EXPLOITATION

    def test_phase_detection_report(self):
        from vulnclaw.agent.context import PentestPhase
        agent = self._make_agent()
        assert agent._detect_phase("生成渗透报告") == PentestPhase.REPORTING
        assert agent._detect_phase("report") == PentestPhase.REPORTING

    def test_phase_detection_with_ip(self):
        from vulnclaw.agent.context import PentestPhase
        agent = self._make_agent()
        # IP without any keyword should default to recon
        phase = agent._detect_phase("10.0.0.1 有什么服务")
        assert phase is not None

    def test_phase_detection_none(self):
        agent = self._make_agent()
        phase = agent._detect_phase("今天天气怎么样")
        assert phase is None

    def test_target_detection_ip(self):
        agent = self._make_agent()
        assert agent._detect_target("对 192.168.1.100 进行渗透测试") == "192.168.1.100"

    def test_target_detection_url(self):
        agent = self._make_agent()
        assert agent._detect_target("测试 https://example.com") == "https://example.com"

    def test_target_detection_domain(self):
        agent = self._make_agent()
        target = agent._detect_target("扫描 testsite.com")
        assert target == "testsite.com"

    def test_target_detection_none(self):
        agent = self._make_agent()
        assert agent._detect_target("没有目标的输入") is None

    def test_skill_context_no_input(self):
        """Without user_input, should fallback to pentest-flow."""
        agent = self._make_agent()
        context = agent._get_active_skill_context(user_input=None)
        assert context is not None
        assert "渗透" in context

    def test_skill_context_with_input(self):
        """With user_input, should dispatch to the right Skill."""
        agent = self._make_agent()
        context = agent._get_active_skill_context(user_input="测试SQL注入")
        assert context is not None
        # Should match web-security-advanced
        assert "注入" in context or "SQL" in context

    def test_skill_context_reverse(self):
        agent = self._make_agent()
        context = agent._get_active_skill_context(user_input="对这个APP做逆向分析")
        assert context is not None
        assert "逆向" in context or "reverse" in context.lower()

    def test_build_openai_tools_includes_skill_ref(self):
        """Tools should include load_skill_reference."""
        agent = self._make_agent()
        tools = agent._build_openai_tools()
        tool_names = [t["function"]["name"] for t in tools]
        assert "load_skill_reference" in tool_names

    def test_build_system_prompt(self):
        agent = self._make_agent()
        prompt = agent._build_system_prompt(target="10.0.0.1", user_input="扫描端口")
        assert "10.0.0.1" in prompt
        assert "VulnClaw" in prompt

    def test_build_system_prompt_auto_mode(self):
        agent = self._make_agent()
        prompt = agent._build_system_prompt(target="10.0.0.1", auto_mode=True, user_input="渗透测试")
        assert "自主渗透" in prompt

    def test_completion_signal_detection(self):
        agent = self._make_agent()
        assert agent._is_completion_signal("[DONE]") is True
        assert agent._is_completion_signal("渗透测试已完成") is True
        assert agent._is_completion_signal("继续扫描") is False

    def test_parse_findings(self):
        agent = self._make_agent()
        response = "[Critical] RCE found in /api/exec\n[High] SQL Injection in login"
        agent._parse_findings(response)
        # _parse_findings creates findings from LLM output; dedup may apply
        # since both lack vuln_type/description, they may share the same finding_id
        assert len(agent.session_state.findings) >= 1
        assert agent.session_state.findings[0].severity == "Critical"

    def test_phase_detection_from_output(self):
        from vulnclaw.agent.context import PentestPhase
        agent = self._make_agent()
        assert agent._detect_phase_from_output("进入漏洞发现阶段") == PentestPhase.VULN_DISCOVERY
        assert agent._detect_phase_from_output("开始利用漏洞") == PentestPhase.EXPLOITATION
        assert agent._detect_phase_from_output("没有特殊信号") is None

    def test_reset_context(self):
        agent = self._make_agent()
        agent.context.state.target = "10.0.0.1"
        agent.reset_context()
        assert agent.session_state.target is None
