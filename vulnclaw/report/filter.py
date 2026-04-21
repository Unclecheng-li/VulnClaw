"""VulnClaw Report Content Filter — clean raw LLM output into pure report text.

过滤目标:
    - TOOL_CALL 标记和内容
    - Python 代码块（print/open/import 等）
    - Round/Context 标记
    - 调试输出
    - think 标签内容

只输出纯净的 Markdown 报告文本。
"""

from __future__ import annotations

import re
from typing import Optional


class ReportContentFilter:
    """报告内容过滤器 — 从 LLM 原始输出中提取纯净报告文本."""

    # ── 过滤模式 ──────────────────────────────────────────────────────────

    # TOOL_CALL 标记（多种格式）
    TOOL_CALL_PATTERNS = [
        # 标准格式
        re.compile(r'\[TOOL_CALL\]\s*\{[^}]+\}', re.DOTALL),
        # 带 tool => 格式
        re.compile(r'\[TOOL_CALL\]\s*\{tool\s*=>\s*"[^"]+"\s*,\s*args\s*=>\s*\{[^}]+\}', re.DOTALL),
        # python_execute 格式
        re.compile(r'\{tool\s*=>\s*"python_execute"\s*,\s*args\s*=>\s*\{[^}]+\}', re.DOTALL),
        # nmap_scan 格式
        re.compile(r'\{tool\s*=>\s*"nmap_scan"\s*,\s*args\s*=>\s*\{[^}]+\}', re.DOTALL),
        # fetch 格式
        re.compile(r'\[TOOL_CALL\]\s*```\s*\{[^}]+\}\s*```', re.DOTALL),
        # 简化的工具调用
        re.compile(r'\[TOOL_CALL\]\s*[\s\S]+?\[/TOOL_CALL\]'),
        # tool_call 格式
        re.compile(r'tool_call\s*\(\s*\{[^}]+\}\s*\)', re.DOTALL),
    ]

    # Round 标记
    ROUND_PATTERNS = [
        re.compile(r'──\s*Cycle\s*\d+\s*\|\s*Round\s*\d+\s*──', re.DOTALL),
        re.compile(r'──\s*Round\s*\d+\s*──', re.DOTALL),
        re.compile(r'Cycle\s*\d+\s*\|\s*Round\s*\d+', re.IGNORECASE),
        re.compile(r'Round\s+\d+:', re.IGNORECASE),
        re.compile(r'第\s*\d+\s*轮', re.IGNORECASE),
    ]

    # think 标签（LLM 思考过程）
    THINK_PATTERNS = [
        re.compile(r'<thinking>[\s\S]*?</thinking>', re.IGNORECASE),
        re.compile(r'<reasoning>[\s\S]*?</reasoning>', re.IGNORECASE),
        re.compile(r'\[think\]', re.IGNORECASE),
        re.compile(r'##\s*思考\s*', re.IGNORECASE),
        re.compile(r'###\s*推理\s*', re.IGNORECASE),
    ]

    # Python 代码块（多种格式）
    PYTHON_CODE_PATTERNS = [
        # 标准 ```python ``` 格式
        re.compile(r'```python\s*[\s\S]*?```'),
        # ``` ``` 格式（无语言标识）
        re.compile(r'```\s*[\s\S]*?```'),
        # 单行 print/import 语句
        re.compile(r'^\s*print\s*\(', re.MULTILINE),
        re.compile(r'^\s*import\s+', re.MULTILINE),
        re.compile(r'^\s*from\s+\w+\s+import', re.MULTILINE),
        re.compile(r'^\s*with\s+open\s*\(', re.MULTILINE),
        # with 语句
        re.compile(r'with\s+open\s*\([^)]+\)\s+as\s+\w+:', re.DOTALL),
        # if __name__ == "__main__"
        re.compile(r'if\s+__name__\s*==\s*["\']__main__["\']:', re.DOTALL),
    ]

    # 调试输出标记
    DEBUG_PATTERNS = [
        re.compile(r'^\s*──.*──\s*$', re.MULTILINE),  # 分隔线
        re.compile(r'^\s*\[=\]+\s*$', re.MULTILINE),  # ===== 样式
        re.compile(r'工具调用|tool_call', re.IGNORECASE),
        re.compile(r'调用工具|调用结果', re.IGNORECASE),
        re.compile(r'\[LLM\s+[A-Z_]+\]', re.IGNORECASE),  # [LLM THINKING] 等
    ]

    # HTTP 请求/响应（可选过滤）
    HTTP_PATTERNS = [
        re.compile(r'HTTP/\d\.\d\s+\d+\s+[^\n]+', re.IGNORECASE),
        re.compile(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+/[^\n]+', re.MULTILINE | re.IGNORECASE),
    ]

    # 阶段切换标记
    PHASE_PATTERNS = [
        re.compile(r'阶段切换\s*[→\-]>\s*\w+', re.IGNORECASE),
        re.compile(r'进入\s*\w+\s*阶段', re.IGNORECASE),
        re.compile(r'当前阶段:\s*\w+', re.IGNORECASE),
    ]

    @classmethod
    def filter(cls, content: str) -> str:
        """过滤内容，只保留纯净的报告文本.

        Args:
            content: LLM 原始输出

        Returns:
            过滤后的纯净报告文本
        """
        result = content

        # 1. 移除 TOOL_CALL 块
        result = cls._remove_tool_calls(result)

        # 2. 移除 Round 标记
        result = cls._remove_round_markers(result)

        # 3. 移除 think 标签
        result = cls._remove_think_tags(result)

        # 4. 移除 Python 代码块
        result = cls._remove_python_code(result)

        # 5. 移除调试输出
        result = cls._remove_debug_output(result)

        # 6. 移除阶段切换标记
        result = cls._remove_phase_markers(result)

        # 7. 清理多余空行
        result = cls._cleanup_whitespace(result)

        return result.strip()

    @classmethod
    def _remove_tool_calls(cls, content: str) -> str:
        """移除 TOOL_CALL 相关内容."""
        result = content

        for pattern in cls.TOOL_CALL_PATTERNS:
            result = pattern.sub('', result)

        # 移除独立的 tool_call 行
        result = re.sub(r'^\s*tool_call\s*\(.*$', '', result, flags=re.MULTILINE)
        result = re.sub(r'^\s*\[TOOL_CALL\]\s*$', '', result, flags=re.MULTILINE)

        return result

    @classmethod
    def _remove_round_markers(cls, content: str) -> str:
        """移除 Round/ Cycle 标记."""
        result = content

        for pattern in cls.ROUND_PATTERNS:
            result = pattern.sub('', result)

        return result

    @classmethod
    def _remove_think_tags(cls, content: str) -> str:
        """移除 think 标签和思考过程."""
        result = content

        for pattern in cls.THINK_PATTERNS:
            result = pattern.sub('', result)

        return result

    @classmethod
    def _remove_python_code(cls, content: str) -> str:
        """移除 Python 代码块.

        注意: 这是过滤 LLM 输出的原始代码，不是报告中的代码示例。
        报告中的代码示例（PoC 等）应该通过模板添加，不是这里处理。
        """
        result = content

        for pattern in cls.PYTHON_CODE_PATTERNS:
            result = pattern.sub('', result)

        # 移除单独的大块 import/print 语句
        lines = result.split('\n')
        filtered_lines = []
        in_code_block = False

        for line in lines:
            # 检测代码块边界
            if line.strip().startswith('```'):
                in_code_block = not in_code_block
                continue

            # 如果在代码块内，跳过
            if in_code_block:
                continue

            # 过滤可疑的代码行
            stripped = line.strip()
            if any(stripped.startswith(prefix) for prefix in [
                'import ', 'from ', 'print(', 'with open', 'if __name__',
                'def ', 'class ', 'return ', 'try:', 'except:',
                'requests.', 'socket.', 'subprocess.',
            ]):
                continue

            filtered_lines.append(line)

        result = '\n'.join(filtered_lines)
        return result

    @classmethod
    def _remove_debug_output(cls, content: str) -> str:
        """移除调试输出."""
        result = content

        for pattern in cls.DEBUG_PATTERNS:
            result = pattern.sub('', result)

        # 移除工具结果标记
        result = re.sub(r'\[结果\]\s*:?\s*', '', result)
        result = re.sub(r'\[输出\]\s*:?\s*', '', result)

        return result

    @classmethod
    def _remove_phase_markers(cls, content: str) -> str:
        """移除阶段切换标记."""
        result = content

        for pattern in cls.PHASE_PATTERNS:
            result = pattern.sub('', result)

        return result

    @classmethod
    def _cleanup_whitespace(cls, content: str) -> str:
        """清理多余空行和空格."""
        # 移除连续的空行（超过2个）
        result = re.sub(r'\n{3,}', '\n\n', content)

        # 移除行首尾空格
        lines = result.split('\n')
        result = '\n'.join(line.strip() for line in lines if line.strip())

        return result

    @classmethod
    def is_pure_markdown(cls, content: str) -> bool:
        """检查内容是否是纯 Markdown（无干扰标记）.

        用于验证过滤结果是否合格。
        """
        # 检查是否包含干扰标记
        interference_patterns = [
            r'\[TOOL_CALL\]',
            r'\{tool\s*=>',
            r'──\s*Round',
            r'──\s*Cycle',
            r'<thinking>',
            r'```python',
            r'^\s*print\s*\(',
            r'^\s*import\s+',
        ]

        for pattern in interference_patterns:
            if re.search(pattern, content, re.MULTILINE):
                return False

        return True


# ── 便捷函数 ────────────────────────────────────────────────────────────────


def filter_report_content(content: str) -> str:
    """过滤报告内容，只保留纯净的 Markdown 文本.

    这是 ReportContentFilter.filter() 的便捷包装。
    """
    return ReportContentFilter.filter(content)


def extract_findings_section(content: str) -> Optional[str]:
    """从报告中提取漏洞列表部分.

    如果找不到专门的漏洞列表，返回 None。
    """
    patterns = [
        r'(##\s*漏洞列表\s*\n[\s\S]*?)(?=##|\Z)',
        r'(##\s*详细发现\s*\n[\s\S]*?)(?=##|\Z)',
        r'(##\s*Findings\s*\n[\s\S]*?)(?=##|\Z)',
    ]

    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def remove_unverified_findings(content: str) -> str:
    """从报告内容中移除未验证的漏洞.

    标记为 [未验证] 的漏洞将被移除。
    """
    # 移除 [未验证] 标记的漏洞章节
    pattern = re.compile(
        r'(###\s*\[[^\]]*\]\s*[^\n]*未验证[^\n]*\n[\s\S]*?)(?=###|\Z)',
        re.IGNORECASE,
    )
    result = pattern.sub('', content)

    # 移除包含 [未验证] 的行
    lines = result.split('\n')
    filtered_lines = []
    skip_section = False

    for line in lines:
        # 检测未验证章节开始
        if '[未验证]' in line and line.strip().startswith('###'):
            skip_section = True
            continue

        # 检测章节结束
        if skip_section and line.startswith('##'):
            skip_section = False

        if not skip_section:
            filtered_lines.append(line)

    return '\n'.join(filtered_lines)
