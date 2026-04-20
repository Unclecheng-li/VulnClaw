"""VulnClaw Skill Dispatcher — match user intents to appropriate Skills."""

from __future__ import annotations

import re
from typing import Any, Optional

from vulnclaw.skills.loader import load_skill_by_name, list_core_skills, list_specialized_skills


# ── Intent → Skill mapping ─────────────────────────────────────────

SKILL_INTENT_MAP: dict[str, list[str]] = {
    # Core skills
    "渗透测试|pentest|全流程|测试一下": ["pentest-flow"],
    "信息收集|侦察|recon|端口扫描|扫描端口|子域名": ["recon"],
    "漏洞发现|漏洞扫描|vulnerability|有什么漏洞": ["vuln-discovery"],
    "漏洞利用|exploit|poc|利用漏洞": ["exploitation"],
    "后渗透|post-exploitation": ["post-exploitation"],
    "报告|report|生成报告": ["reporting"],
    "绕过waf|waf绕过|waf bypass": ["waf-bypass"],
    # Specialized skills — original
    "web渗透|web测试|网站测试": ["web-pentest"],
    "安卓|android|apk|app测试": ["android-pentest"],
    # Specialized skills — from Sec-Skill
    "逆向|reverse|签名恢复|burp重放|js签名|客户端逆向|请求链|重放|签名": ["client-reverse"],
    "抓包|packet|frida|jadx|hook|ssl pinning|scrcpy": ["client-reverse"],
    "浏览器签名|反爬|antibot|token生成|cookie跳转": ["client-reverse"],
    "web高级|注入|sql注入|xss|ssrf|ssti|xxe|命令注入|反序列化|rce|远程代码执行": ["web-security-advanced"],
    "cors|graphql|websocket|oauth|请求走私|jwt|csrf|原型污染": ["web-security-advanced"],
    "认证漏洞|逻辑漏洞|越权|idor|支付逻辑|文件上传|路径穿越": ["web-security-advanced"],
    "ai安全|mcp安全|prompt注入|工具滥用|agent安全|模型安全": ["ai-mcp-security"],
    "ai渗透|大模型安全|llm安全|prompt injection|tool abuse": ["ai-mcp-security"],
    "mcp投毒|skills供应链|角色逃逸|数据泄露|prompt泄漏": ["ai-mcp-security"],
    "内网渗透|横向移动|提权|持久化|隧道|代理|域渗透|ad攻击": ["intranet-pentest-advanced"],
    "adcs|exchange|sharepoint|mimikatz|kerberoasting|dcsync|pth": ["intranet-pentest-advanced"],
    "凭据窃取|bloodhound|frp|chisel|ligolo|amsi绕过": ["intranet-pentest-advanced"],
    "工具|命令|编码|解码|reverse shell|密码攻击|hashcat": ["pentest-tools"],
    "sqlmap|nmap|nuclei|ffuf|burp|impacket|crackmapexec": ["pentest-tools"],
    "速查|payload|绕过提醒|快速验证|checklist|检查清单": ["rapid-checklist"],
    "payload大全|绕过|bypass|快速查|速查卡|快速回忆": ["rapid-checklist"],
    # Crypto toolkit
    "编码|解码|base64|base32|hex|url编码|加密|解密|哈希|hash": ["crypto-toolkit"],
    "md5|sha|aes|des|rsa|jwt|rot13|caesar|morse|栅栏": ["crypto-toolkit"],
    "base64解码|base64编码|hex解码|url解码|unicode解码|html解码": ["crypto-toolkit"],
    "密码学|crypto|cipher|decrypt|encrypt|encode|decode": ["crypto-toolkit"],
    "摩尔电码|凯撒密码|维吉尼亚|培根密码|base58": ["crypto-toolkit"],
    # ── CTF specialized skills ──────────────────────────────────────
    # ctf-web: CTF Web 攻击知识库
    "ctf|夺旗|flag|弱比较|空格绕过|正则绕过|rce|代码审计|eval绕过|highlight_file": ["ctf-web"],
    "0e|md5绕过|preg_match绕过|类型绕过|type juggling|弱类型": ["ctf-web"],
    "回显|无回显|blind rce|命令执行绕过|php代码审计|ssti注入": ["ctf-web"],
    # ctf-crypto: CTF 密码学攻击知识库
    "rsa攻击|小指数|共模攻击|wiener|coppersmith|padding oracle": ["ctf-crypto"],
    "ecc攻击|小子群|离散对数|ecdsa|ed25519|pohlig-hellman": ["ctf-crypto"],
    "lfsr|lcg|prng|mt19937|随机数预测|流密码": ["ctf-crypto"],
    "lwe|格攻击|lll|cvp|svp|格基规约": ["ctf-crypto"],
    "古典密码|维吉尼亚|凯撒|栅栏|替换密码|频率分析": ["ctf-crypto"],
    # ctf-misc: CTF 杂项知识库
    "pyjail|python沙箱|jail逃逸|sandbox_escape|python jail": ["ctf-misc"],
    "bashjail|bash沙箱|restricted shell|rbash逃逸": ["ctf-misc"],
    "编码链|多层编码|杂项|misc|隐写|stego": ["ctf-misc"],
    "ctfd|夺旗平台|flag提交|题目下载": ["ctf-misc"],
    # ── OSINT specialized skill — refined routing ───────────────────
    # osint-recon: Full-dimension recon (OSINT + social engineering)
    # Triggered only when user explicitly mentions social engineering / OSINT / author tracking
    "社会工程|社工|作者追踪|人物追踪|目标画像|人物画像": ["osint-recon"],
    "跨平台|用户名搜索|身份关联|github追踪|bilibili追踪": ["osint-recon"],
    # Full/deep recon — trigger osint-recon for comprehensive 4-dimension collection
    "全面侦察|深度侦察|完整信息收集|全面信息收集|深度收集|搜集基础信息": ["osint-recon"],
}


class SkillDispatcher:
    """Dispatches user input to the most appropriate Skill."""

    def dispatch(self, user_input: str) -> Optional[dict[str, Any]]:
        """Match user input to a Skill and load it.

        Args:
            user_input: Natural language input from the user.

        Returns:
            Loaded skill dict, or None if no match found.
        """
        input_lower = user_input.lower()

        # Score each skill based on keyword matches
        scores: dict[str, float] = {}

        for pattern, skill_names in SKILL_INTENT_MAP.items():
            keywords = pattern.split("|")
            match_count = sum(1 for kw in keywords if kw in input_lower)
            if match_count > 0:
                for skill_name in skill_names:
                    score = match_count / len(keywords)
                    # Specialized skills get a 1.5x boost over core skills
                    # to ensure more specific matches win over generic ones
                    skill = load_skill_by_name(skill_name)
                    if skill and skill.get("format") == "directory":
                        score *= 1.5
                    scores[skill_name] = scores.get(skill_name, 0) + score

        if not scores:
            # Default to pentest-flow
            return load_skill_by_name("pentest-flow")

        # Load the highest-scoring skill
        best_skill_name = max(scores, key=scores.get)  # type: ignore[arg-type]
        return load_skill_by_name(best_skill_name)

    def list_all_skills(self) -> list[dict[str, str]]:
        """List all available skills with name and description."""
        skills = []
        for name in list_core_skills():
            skill = load_skill_by_name(name)
            if skill:
                skills.append({
                    "name": skill["name"],
                    "description": skill.get("description", ""),
                    "type": "core",
                    "format": skill.get("format", "flat"),
                    "references": str(len(skill.get("references", []))),
                })
        for name in list_specialized_skills():
            skill = load_skill_by_name(name)
            if skill:
                skills.append({
                    "name": skill["name"],
                    "description": skill.get("description", ""),
                    "type": "specialized",
                    "format": skill.get("format", "flat"),
                    "references": str(len(skill.get("references", []))),
                })
        return skills
