"""VulnClaw Skill Module Tests — loader.py + dispatcher.py"""

import pytest
from pathlib import Path


# ── loader.py ────────────────────────────────────────────────────────

class TestSkillLoader:
    """Test Skill loading and management."""

    def test_list_core_skills(self):
        from vulnclaw.skills.loader import list_core_skills
        core = list_core_skills()
        assert isinstance(core, list)
        assert len(core) == 7
        expected = ["pentest-flow", "recon", "vuln-discovery", "exploitation",
                     "post-exploitation", "reporting", "waf-bypass"]
        for skill in expected:
            assert skill in core, f"Missing core skill: {skill}"

    def test_list_specialized_skills(self):
        from vulnclaw.skills.loader import list_specialized_skills
        spec = list_specialized_skills()
        assert isinstance(spec, list)
        assert len(spec) == 8
        expected = ["web-pentest", "android-pentest", "client-reverse",
                     "web-security-advanced", "ai-mcp-security",
                     "intranet-pentest-advanced", "pentest-tools", "rapid-checklist"]
        for skill in expected:
            assert skill in spec, f"Missing specialized skill: {skill}"

    def test_load_core_skill(self):
        from vulnclaw.skills.loader import load_core_skill
        skill = load_core_skill("pentest-flow")
        assert skill is not None
        assert "content" in skill
        assert "渗透" in skill["content"]

    def test_load_skill_by_name_core(self):
        from vulnclaw.skills.loader import load_skill_by_name
        skill = load_skill_by_name("pentest-flow")
        assert skill is not None
        assert skill["name"] == "pentest-flow"

    def test_load_skill_by_name_specialized(self):
        from vulnclaw.skills.loader import load_skill_by_name
        skill = load_skill_by_name("client-reverse")
        assert skill is not None
        assert skill["name"] == "client-reverse"

    def test_load_nonexistent_skill(self):
        from vulnclaw.skills.loader import load_skill_by_name
        skill = load_skill_by_name("nonexistent-skill")
        assert skill is None

    def test_skill_has_description(self):
        from vulnclaw.skills.loader import load_skill_by_name
        for name in ["pentest-flow", "recon", "client-reverse", "web-security-advanced"]:
            skill = load_skill_by_name(name)
            assert skill is not None
            assert "description" in skill
            assert len(skill["description"]) > 0, f"Skill {name} has empty description"

    def test_skill_format_field(self):
        """Directory-format skills should have format='directory'."""
        from vulnclaw.skills.loader import load_skill_by_name
        # Core skills are flat format
        pentest = load_skill_by_name("pentest-flow")
        assert pentest["format"] == "flat"
        # Specialized skills are directory format
        client_rev = load_skill_by_name("client-reverse")
        assert client_rev["format"] == "directory"

    def test_directory_skill_has_references(self):
        """Directory-format skills should list their reference files."""
        from vulnclaw.skills.loader import load_skill_by_name
        skill = load_skill_by_name("client-reverse")
        assert "references" in skill
        assert len(skill["references"]) > 0
        # Should be a list of filenames
        for ref in skill["references"]:
            assert isinstance(ref, str)
            assert ref.endswith(".md") or ref.endswith(".yaml")

    def test_flat_skill_no_references(self):
        """Flat-format core skills should have empty references."""
        from vulnclaw.skills.loader import load_skill_by_name
        skill = load_skill_by_name("pentest-flow")
        assert skill.get("references", []) == []

    def test_load_skill_reference(self):
        """Test loading a specific reference file from a skill."""
        from vulnclaw.skills.loader import load_skill_reference
        content = load_skill_reference("client-reverse", "02-client-api-reverse-and-burp.md")
        assert content is not None
        assert len(content) > 100
        assert "client" in content.lower() or "burp" in content.lower() or "reverse" in content.lower()

    def test_load_skill_reference_nonexistent(self):
        from vulnclaw.skills.loader import load_skill_reference
        content = load_skill_reference("client-reverse", "nonexistent.md")
        assert content is None

    def test_load_skill_reference_wrong_skill(self):
        from vulnclaw.skills.loader import load_skill_reference
        content = load_skill_reference("nonexistent-skill", "some.md")
        assert content is None

    def test_all_specialized_skills_loadable(self):
        """Every specialized skill should load successfully."""
        from vulnclaw.skills.loader import list_specialized_skills, load_skill_by_name
        for name in list_specialized_skills():
            skill = load_skill_by_name(name)
            assert skill is not None, f"Failed to load skill: {name}"
            assert "content" in skill, f"Skill {name} has no content"
            assert len(skill["content"]) > 50, f"Skill {name} has suspiciously short content"

    def test_all_core_skills_loadable(self):
        """Every core skill should load successfully."""
        from vulnclaw.skills.loader import list_core_skills, load_skill_by_name
        for name in list_core_skills():
            skill = load_skill_by_name(name)
            assert skill is not None, f"Failed to load skill: {name}"

    def test_reference_count_per_specialized_skill(self):
        """Each specialized skill should have at least 1 reference file."""
        from vulnclaw.skills.loader import list_specialized_skills, load_skill_by_name
        for name in list_specialized_skills():
            skill = load_skill_by_name(name)
            refs = skill.get("references", [])
            assert len(refs) >= 1, f"Skill {name} has no reference files"

    def test_specific_reference_files_exist(self):
        """Check key reference files exist for each specialized skill."""
        from vulnclaw.skills.loader import load_skill_by_name
        test_cases = [
            ("client-reverse", "02-client-api-reverse-and-burp.md"),
            ("web-security-advanced", "web-injection.md"),
            ("ai-mcp-security", "ai-app-security.md"),
            ("intranet-pentest-advanced", "06-intranet-and-host-operations-integrated.md"),
            ("pentest-tools", "05-tools-and-operations-integrated.md"),
            ("rapid-checklist", "payloads.md"),
            ("web-pentest", "03-web-security-integrated.md"),
            ("android-pentest", "android-authorized-app-pentest-sop.md"),
        ]
        for skill_name, ref_name in test_cases:
            skill = load_skill_by_name(skill_name)
            assert ref_name in skill.get("references", []), \
                f"Skill {skill_name} missing reference: {ref_name}"


# ── dispatcher.py ────────────────────────────────────────────────────

class TestSkillDispatcher:
    """Test Skill dispatching based on user input."""

    def _make_dispatcher(self):
        from vulnclaw.skills.dispatcher import SkillDispatcher
        return SkillDispatcher()

    def test_dispatch_pentest_flow(self):
        d = self._make_dispatcher()
        skill = d.dispatch("对目标进行渗透测试")
        assert skill["name"] == "pentest-flow"

    def test_dispatch_recon(self):
        d = self._make_dispatcher()
        skill = d.dispatch("信息收集 侦察目标")
        assert skill["name"] == "recon"

    def test_dispatch_vuln_discovery(self):
        d = self._make_dispatcher()
        skill = d.dispatch("漏洞扫描发现漏洞")
        assert skill["name"] == "vuln-discovery"

    def test_dispatch_exploitation(self):
        d = self._make_dispatcher()
        skill = d.dispatch("exploit利用漏洞")
        assert skill["name"] == "exploitation"

    def test_dispatch_post_exploitation(self):
        d = self._make_dispatcher()
        skill = d.dispatch("后渗透post-exploitation")
        assert skill["name"] == "post-exploitation"

    def test_dispatch_reporting(self):
        d = self._make_dispatcher()
        skill = d.dispatch("生成报告report")
        assert skill["name"] == "reporting"

    def test_dispatch_waf_bypass(self):
        d = self._make_dispatcher()
        skill = d.dispatch("绕过waf")
        assert skill["name"] == "waf-bypass"

    def test_dispatch_web_pentest(self):
        d = self._make_dispatcher()
        skill = d.dispatch("web渗透测试网站")
        assert skill["name"] == "web-pentest"

    def test_dispatch_android_pentest(self):
        d = self._make_dispatcher()
        skill = d.dispatch("安卓android apk测试")
        assert skill["name"] == "android-pentest"

    def test_dispatch_client_reverse(self):
        d = self._make_dispatcher()
        skill = d.dispatch("逆向分析签名恢复")
        assert skill["name"] == "client-reverse"

    def test_dispatch_web_security_advanced(self):
        d = self._make_dispatcher()
        skill = d.dispatch("sql注入xss测试")
        assert skill["name"] == "web-security-advanced"

    def test_dispatch_ai_mcp_security(self):
        d = self._make_dispatcher()
        skill = d.dispatch("AI安全MCP安全评估")
        assert skill["name"] == "ai-mcp-security"

    def test_dispatch_intranet(self):
        d = self._make_dispatcher()
        skill = d.dispatch("内网横向移动域渗透")
        assert skill["name"] == "intranet-pentest-advanced"

    def test_dispatch_pentest_tools(self):
        d = self._make_dispatcher()
        skill = d.dispatch("nmap命令速查工具")
        assert skill["name"] == "pentest-tools"

    def test_dispatch_rapid_checklist(self):
        d = self._make_dispatcher()
        skill = d.dispatch("快速XSS payload速查")
        assert skill["name"] == "rapid-checklist"

    def test_dispatch_default_to_pentest_flow(self):
        """Unrecognized input should default to pentest-flow."""
        d = self._make_dispatcher()
        skill = d.dispatch("你好今天天气怎么样")
        assert skill["name"] == "pentest-flow"

    def test_dispatch_returns_dict(self):
        d = self._make_dispatcher()
        skill = d.dispatch("渗透测试")
        assert isinstance(skill, dict)
        assert "name" in skill
        assert "content" in skill
        assert "description" in skill

    def test_dispatch_specialized_over_core(self):
        """Specialized skills should win over core skills for specific inputs."""
        d = self._make_dispatcher()
        # "内网" could match post-exploitation (core) or intranet-pentest-advanced (specialized)
        # With the 1.5x boost, specialized should win for specific intranet keywords
        skill = d.dispatch("内网渗透横向移动")
        assert skill["name"] == "intranet-pentest-advanced"

    def test_dispatch_case_insensitive(self):
        """Dispatch should be case-insensitive."""
        d = self._make_dispatcher()
        skill1 = d.dispatch("SQL注入")
        skill2 = d.dispatch("sql注入")
        assert skill1["name"] == skill2["name"]
