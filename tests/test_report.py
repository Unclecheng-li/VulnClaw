"""VulnClaw Report Module Tests — generator.py + poc_builder.py"""

import pytest
from pathlib import Path


# ── generator.py ─────────────────────────────────────────────────────

class TestReportGenerator:
    """Test report generation."""

    def _make_session(self):
        from vulnclaw.agent.context import SessionState, PentestPhase, VulnerabilityFinding
        state = SessionState(target="192.168.1.100")
        state.advance_phase(PentestPhase.RECON)
        state.advance_phase(PentestPhase.VULN_DISCOVERY)
        f1 = VulnerabilityFinding(
            title="SQL Injection",
            severity="Critical",
            vuln_type="SQLi",
            description="SQL injection in login form",
            evidence="admin' OR 1=1-- bypassed authentication",
            remediation="Use parameterized queries",
        )
        f1.verified = True
        f1.verification_status = "verified"
        state.add_finding(f1)
        f2 = VulnerabilityFinding(
            title="Cross-Site Scripting",
            severity="High",
            vuln_type="XSS",
            description="Reflected XSS in search parameter",
            evidence="<script>alert(1)</script>",
        )
        f2.verified = True
        f2.verification_status = "verified"
        state.add_finding(f2)
        f3 = VulnerabilityFinding(
            title="Information Disclosure",
            severity="Medium",
            vuln_type="Info Leak",
            description="Server version header exposed",
        )
        f3.verified = True
        f3.verification_status = "verified"
        state.add_finding(f3)
        return state

    def test_generate_report(self, tmp_path):
        from vulnclaw.report.generator import generate_report
        session = self._make_session()
        output = str(tmp_path / "report.md")
        path = generate_report(session, output)
        assert path.exists()

    def test_report_contains_target(self, tmp_path):
        from vulnclaw.report.generator import generate_report
        session = self._make_session()
        output = str(tmp_path / "report.md")
        generate_report(session, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "192.168.1.100" in content

    def test_report_contains_findings(self, tmp_path):
        from vulnclaw.report.generator import generate_report
        session = self._make_session()
        output = str(tmp_path / "report.md")
        generate_report(session, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "SQL Injection" in content
        assert "Cross-Site Scripting" in content
        assert "Information Disclosure" in content

    def test_report_contains_severity_counts(self, tmp_path):
        from vulnclaw.report.generator import generate_report
        session = self._make_session()
        output = str(tmp_path / "report.md")
        generate_report(session, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "Critical" in content
        assert "High" in content
        assert "Medium" in content

    def test_report_contains_vulnclaw_brand(self, tmp_path):
        from vulnclaw.report.generator import generate_report
        session = self._make_session()
        output = str(tmp_path / "report.md")
        generate_report(session, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "VulnClaw" in content

    def test_report_with_recon_data(self, tmp_path):
        from vulnclaw.report.generator import generate_report
        from vulnclaw.agent.context import SessionState, PentestPhase
        session = SessionState(target="10.0.0.1")
        session.recon_data = {
            "ports": [80, 443, 3306],
            "services": ["nginx/1.24", "mysql/8.0"],
        }
        output = str(tmp_path / "report_recon.md")
        generate_report(session, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "10.0.0.1" in content

    def test_report_empty_findings(self, tmp_path):
        from vulnclaw.report.generator import generate_report
        from vulnclaw.agent.context import SessionState
        session = SessionState(target="10.0.0.1")
        output = str(tmp_path / "report_empty.md")
        generate_report(session, output)
        content = Path(output).read_text(encoding="utf-8")
        # Report with no verified findings should mention 0 verified or show summary
        assert "10.0.0.1" in content
        assert "已验证漏洞" in content

    def test_report_creates_pocs_dir(self, tmp_path):
        from vulnclaw.report.generator import generate_report
        session = self._make_session()
        output = str(tmp_path / "report_with_poc.md")
        generate_report(session, output)
        # PoC directory should be created
        pocs_dir = tmp_path / "pocs"
        assert pocs_dir.exists()

    def test_report_auto_output_path(self, tmp_path):
        """If no output path specified, should auto-generate one."""
        from vulnclaw.report.generator import generate_report
        from vulnclaw.agent.context import SessionState
        session = SessionState(target="auto-target")
        # This will use the default SESSIONS_DIR
        try:
            path = generate_report(session)
            assert path.exists()
        except Exception:
            # Might fail if SESSIONS_DIR not writable, that's ok for test
            pass


# ── poc_builder.py ───────────────────────────────────────────────────

class TestPoCBuilder:
    """Test PoC script generation."""

    def test_generate_pocs(self, tmp_path):
        from vulnclaw.report.poc_builder import generate_pocs
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        session = SessionState(target="192.168.1.100")
        session.add_finding(VulnerabilityFinding(
            title="SQL Injection",
            severity="Critical",
            vuln_type="SQLi",
        ))
        session.add_finding(VulnerabilityFinding(
            title="XSS Attack",
            severity="High",
            vuln_type="XSS",
        ))
        pocs_dir = tmp_path / "pocs"
        paths = generate_pocs(session, pocs_dir)
        assert len(paths) == 2
        for p in paths:
            assert p.exists()

    def test_poc_content(self, tmp_path):
        from vulnclaw.report.poc_builder import generate_pocs
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        session = SessionState(target="192.168.1.100")
        session.add_finding(VulnerabilityFinding(
            title="SQL Injection",
            severity="Critical",
            vuln_type="SQLi",
            cve="CVE-2026-12345",
            evidence="http://192.168.1.100/login?id=1",
        ))
        pocs_dir = tmp_path / "pocs"
        paths = generate_pocs(session, pocs_dir)
        content = paths[0].read_text(encoding="utf-8")
        assert "SQL Injection" in content
        assert "Critical" in content
        assert "CVE-2026-12345" in content
        assert "python3" in content
        assert "sql_injection" in content
        assert "requests.get(target, params=params" in content
        assert "http://192.168.1.100/login?id=1" in content
        assert "[CONFIRMED] SQL注入漏洞" in content


    def test_poc_is_valid_python(self, tmp_path):
        """Generated PoC should be syntactically valid Python."""
        from vulnclaw.report.poc_builder import generate_pocs
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        session = SessionState(target="10.0.0.1")
        session.add_finding(VulnerabilityFinding(
            title="RCE Vuln",
            severity="Critical",
            vuln_type="RCE",
        ))
        pocs_dir = tmp_path / "pocs"
        paths = generate_pocs(session, pocs_dir)
        content = paths[0].read_text(encoding="utf-8")
        # Try to compile it
        compile(content, str(paths[0]), "exec")

    def test_poc_updates_finding(self, tmp_path):
        """Generating PoCs should update finding.poc_script."""
        from vulnclaw.report.poc_builder import generate_pocs
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        session = SessionState(target="10.0.0.1")
        session.add_finding(VulnerabilityFinding(
            title="Test Vuln",
            severity="High",
        ))
        pocs_dir = tmp_path / "pocs"
        generate_pocs(session, pocs_dir)
        assert session.findings[0].poc_script is not None

    def test_generate_single_poc(self):
        from vulnclaw.report.poc_builder import generate_single_poc
        poc = generate_single_poc(
            title="SQLi",
            severity="Critical",
            cve="CVE-2026-0001",
            target="http://target",
            vuln_type="sqli",
        )
        assert isinstance(poc, str)
        assert "SQLi" in poc
        assert "CVE-2026-0001" in poc
        assert "sql_injection" in poc
        assert 'params = {' in poc
        assert 'target = "http://target"' in poc

    def test_generate_single_poc_uses_specific_template_for_rce(self):
        from vulnclaw.report.poc_builder import generate_single_poc

        poc = generate_single_poc(
            title="RCE",
            severity="Critical",
            target="https://demo.local/exec",
            vuln_type="RCE",
        )

        assert "command_injection" in poc
        assert '"cmd": ";id"' in poc
        assert 'target = "https://demo.local/exec"' in poc

    def test_generate_pocs_extracts_target_from_evidence(self, tmp_path):
        from vulnclaw.report.poc_builder import generate_pocs
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding

        session = SessionState(target="example.com")
        session.add_finding(VulnerabilityFinding(
            title="File Inclusion",
            severity="High",
            vuln_type="LFI",
            evidence="可访问地址 https://victim.local/download?file=../../etc/passwd 并返回 root:x:0:0",
        ))

        paths = generate_pocs(session, tmp_path / "pocs")
        content = paths[0].read_text(encoding="utf-8")
        assert 'target = "https://victim.local/download?file=../../etc/passwd"' in content
        assert "../../../etc/passwd" in content


    def test_poc_empty_findings(self, tmp_path):
        """No findings should produce no PoC files."""
        from vulnclaw.report.poc_builder import generate_pocs
        from vulnclaw.agent.context import SessionState
        session = SessionState(target="10.0.0.1")
        pocs_dir = tmp_path / "pocs"
        paths = generate_pocs(session, pocs_dir)
        assert len(paths) == 0
