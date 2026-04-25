"""VulnClaw Finding Parser — three-layer vulnerability detection from LLM responses."""

from __future__ import annotations

import re
from typing import Any

from vulnclaw.agent.context import ContextManager, VulnerabilityFinding
from vulnclaw.agent.runtime_state import RuntimeState
from vulnclaw.agent.think_filter import strip_think_tags



# ── Proof patterns: indicators that a vulnerability claim has real evidence ──
PROOF_PATTERNS: list[str] = [
    r'差异[：:]*\s*\d+',          # 差异:155 / 差异 306
    r'\d+\s*bytes|\d+\s*字节',    # 52095 bytes / 长度 52095
    r'(?:状态|响应)?[码代码]*[:：]*\s*5\d{2}',  # 500错误 / 状态码:500
    r'SQL.*错误|mysql.*error|sql.*error',
    r'SLEEP\(|BENCHMARK\(|EXTRACTVALUE\(|UPDATEXML\(',
    r'命令执行成功|whoami|id\s+',
    r'root[:\s]|administrator',   # privilege indicator
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # internal IP leaked
    r'CVE-\d{4}-\d{4,}',         # CVE mentioned (already a strong signal)
    r'成功提取|成功获取|获取到',   # data extraction success
]

# ── Natural-language vulnerability patterns ─────────────────────────────────
NATURAL_LANG_PATTERNS: list[tuple[str, str, str]] = [
    # ── Critical / High severity ──────────────────────────────────────
    (r'SQL注入|SQLi|注入漏洞', "High", "SQL注入"),
    (r'RCE|远程代码执行|命令注入|命令执行', "Critical", "远程代码执行"),
    (r'未授权|未认证|无需认证|认证绕过|认证.*绕过', "High", "认证绕过"),
    (r'SSRF|服务端请求伪造', "High", "SSRF"),
    # ── Medium severity ───────────────────────────────────────────────
    (r'XSS|跨站脚本|存储型XSS|反射型XSS', "Medium", "XSS跨站脚本"),
    (r'CSRF|跨站请求伪造', "Medium", "CSRF"),
    (r'文件包含|路径遍历|LFI|RFI', "Medium", "文件包含/遍历"),
    (r'弱口令|默认口令|默认密码|暴力破解|爆破', "Medium", "弱口令/暴力破解"),
    (r'配置错误|配置缺陷|泄露.*配置', "Medium", "配置错误"),
    # ── Low / Info ───────────────────────────────────────────────
    (r'敏感目录|敏感文件.*发现|目录.*发现', "Info", "敏感目录/文件发现"),
    (r'版本.*旧|中间件版本|指纹.*识别', "Info", "版本信息"),
    (r'CVE-\d{4}-\d{4,}', "High", "已知CVE漏洞"),
]

# ── Security-relevant keywords for note→finding elevation ──────────────
ELEVATION_KEYWORDS: list[tuple[str, str, str]] = [
    (r'泄露|敏感信息|数据泄露|个人信息|\d+条数据', "High", "数据泄露"),
    (r'未授权|未认证|认证绕过|无需认证', "High", "未授权访问"),
    (r'RCE|命令执行|远程代码', "Critical", "远程代码执行"),
    (r'SQL注入|SQLi|注入', "High", "注入漏洞"),
    (r'CVE-\d{4}-\d{4,}', "High", "已知CVE漏洞"),
    (r'弱口令|默认口令|暴力', "High", "弱口令/暴力破解"),
    (r'XSS|跨站脚本', "Medium", "XSS"),
    (r'文件包含|路径遍历', "High", "文件包含/遍历"),
    (r'返回200.*但.*不存在|200.*空内容|空响应.*但', "Medium", "潜在授权绕过"),
    (r'403.*接口|接口存在.*403', "Medium", "403认证拦截"),
]


class FindingParser:
    """Parses LLM responses to extract vulnerability findings and discoveries."""

    def __init__(self, context: ContextManager, runtime: RuntimeState) -> None:
        self.context = context
        self.runtime = runtime

    def parse(self, response: str) -> None:
        """Three-layer detection:
        1. Explicit [Severity] tags
        2. Natural-language vulnerability descriptions
        3. confirmed_facts elevation
        """
        existing_titles = {f.title for f in self.context.state.findings}

        # ── Layer 1: Explicit severity tags ─────────────────────────────
        severity_patterns = [
            (r'\[Critical\]\s*(.+?)(?:\n|$)', "Critical"),
            (r'\[High\]\s*(.+?)(?:\n|$)', "High"),
            (r'\[Medium\]\s*(.+?)(?:\n|$)', "Medium"),
            (r'\[Low\]\s*(.+?)(?:\n|$)', "Low"),
        ]
        for pattern, severity in severity_patterns:
            for match in re.findall(pattern, response):
                title = match.strip()
                title = re.sub(r'\*+', '', title).strip(' -–—:')
                if title and title not in existing_titles:
                    self.context.state.add_finding(VulnerabilityFinding(
                        title=title,
                        severity=severity,
                    ))
                    existing_titles.add(title)

        # ── Layer 2: Natural-language vulnerability detection ───────────
        _URL_RE = re.compile(r'https?://[^\s<>"\')\]]+')
        _PATH_RE = re.compile(r'(?:/[\w%&=?\-]+)+')

        clean_response = strip_think_tags(response)
        notes = self.context.state.notes
        if notes:
            clean_notes = [strip_think_tags(n) for n in notes[-5:]]
            evidence_pool = clean_response + " " + " ".join(clean_notes)
        else:
            evidence_pool = clean_response

        for pattern, severity, vuln_type in NATURAL_LANG_PATTERNS:
            canonical_title = f"[自动] {vuln_type}"
            if canonical_title in existing_titles:
                continue

            vuln_matches = re.findall(pattern, clean_response, re.IGNORECASE)
            if not vuln_matches:
                continue

            has_proof = any(
                re.search(p, clean_response + " " + " ".join(notes[-3:]), re.IGNORECASE)
                for p in PROOF_PATTERNS
            )
            has_confirmed_fact = any(
                re.search(p, " ".join(getattr(self.context.state, 'confirmed_facts', [])), re.IGNORECASE)
                for p in PROOF_PATTERNS
            )
            if not has_proof and not has_confirmed_fact:
                continue

            proof_snippets = []
            for p in PROOF_PATTERNS:
                for m in re.finditer(p, evidence_pool, re.IGNORECASE):
                    snippet = m.group(0).strip()[:80]
                    if snippet and snippet not in proof_snippets:
                        proof_snippets.append(snippet)
                    if len(proof_snippets) >= 3:
                        break

            urls = re.findall(_URL_RE, evidence_pool)
            paths = re.findall(_PATH_RE, evidence_pool)
            seen, unique_urls, unique_paths = set(), [], []
            for u in urls:
                if u not in seen:
                    seen.add(u)
                    unique_urls.append(u)
            for p2 in paths:
                if p2 not in seen:
                    seen.add(p2)
                    unique_paths.append(p2)

            location = " | ".join(unique_urls[:2] + unique_paths[:2])
            proof_text = " | ".join(proof_snippets) if proof_snippets else ""
            evidence = (location + " | " + proof_text) if proof_text else location

            self.context.state.add_finding(VulnerabilityFinding(
                title=canonical_title,
                severity=severity,
                vuln_type=vuln_type,
                description=f"自动检测：{vuln_matches[0].strip()[:100]}" if vuln_matches else "通过自然语言模式自动检测",
                evidence=evidence[:300],
            ))
            existing_titles.add(canonical_title)

        # ── Layer 3: confirmed_facts → findings elevation ───────────────
        confirmed_facts = getattr(self.context.state, 'confirmed_facts', [])
        for fact in confirmed_facts:
            for pattern, severity, vuln_type in ELEVATION_KEYWORDS:
                if re.search(pattern, fact, re.IGNORECASE):
                    title = f"[已确认] {fact.strip()[:120]}"
                    if title not in existing_titles:
                        finding = VulnerabilityFinding(
                            title=title,
                            severity=severity,
                            vuln_type=vuln_type,
                            description=f"通过工具验证确认：{fact}",
                            verified=True,
                            verification_status="verified",
                        )
                        self.context.state.add_finding(finding)
                        existing_titles.add(title)
                    break

        # ── Extract key discoveries as notes ────────────────────────────
        clean_response = strip_think_tags(response)
        discovery_markers = [
            r'\[\+\]\s*(.+?)(?:\n|$)',
            r'发现[：:]\s*(.+?)(?:\n|$)',
            r'(flag\{[^}]+\})',
            r'(NSSCTF\{[^}]+\})',
            r'(CTF\{[^}]+\})',
        ]
        for pattern in discovery_markers:
            for match in re.findall(pattern, clean_response, re.IGNORECASE):
                note = match.strip()[:200]
                if note and note not in self.context.state.notes:
                    self.context.state.add_note(note)

        # ── Auto-extract confirmed facts ────────────────────────────────
        confirmed_markers = [
            r'已确认[：:]\s*(.+?)(?:\n|$)',
            r'确认[：:]\s*(.+?)(?:\n|$)',
            r'验证成功[：:]\s*(.+?)(?:\n|$)',
            r'\[✅\]\s*(.+?)(?:\n|$)',
            r'确认.*存在',
            r'漏洞.*已确认',
            r'已.*验证.*成功',
            r'payload.*差异[：:]*\s*\d+',
            r'差异[：:]*\s*\d+.*成功',
            r'SLEEP\([^)]+\).*耗时',
            r'成功提取[：:]*\s*\S+',
            r'提取到[：:]*\s*\S+',
            r'命令执行成功',
            r'可提取[：:]*\s*\S+',
            r'布尔.*成功|布尔.*有效',
            r'报错.*成功|报错.*有效',
            r'UNION.*成功|UNION.*有效',
            r'漏洞确认',
        ]
        for pattern in confirmed_markers:
            for match in re.findall(pattern, response, re.IGNORECASE):
                fact = match.strip()[:200]
                if fact and hasattr(self.context.state, 'add_confirmed_fact'):
                    self.context.state.add_confirmed_fact(fact)

        # ── Auto-extract unverified assumptions ─────────────────────────
        assumption_markers = [
            r'假设[：:]\s*(.+?)(?:\n|$)',
            r'推测[：:]\s*(.+?)(?:\n|$)',
        ]
        for pattern in assumption_markers:
            for match in re.findall(pattern, response, re.IGNORECASE):
                assumption = match.strip()[:200]
                if assumption and assumption not in self.runtime.unverified_assumptions:
                    self.runtime.unverified_assumptions.append(assumption)
