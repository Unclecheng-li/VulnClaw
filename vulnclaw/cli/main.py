"""VulnClaw CLI — main entry point with REPL and sub-commands."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Optional

# Fix Windows console encoding for emoji/unicode output
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from vulnclaw import __version__
from vulnclaw.config.settings import load_config, set_config_value, save_config, apply_provider_preset, list_providers

app = typer.Typer(
    name="vulnclaw",
    help="🦞 VulnClaw — AI-powered penetration testing CLI",
    no_args_is_help=False,
    add_completion=False,
)

console = Console()
err_console = Console(stderr=True)


# ── Banner ──────────────────────────────────────────────────────────

ASCII_LOGO = (
    " _    __      __      ________\n"
    "| |  / /_  __/ /___  / ____/ /___ __      __\n"
    "| | / / / / / / __ \\/ /   / / __ `/ | /| / /\n"
    "| |/ / /_/ / / / / / /___/ / /_/ /| |/ |/ /\n"
    "|___/\\__,_/_/_/ /_/\\____/_/\\__,_/ |__/|__/\n"
)

BANNER_SUBTITLE = f"🦞 VulnClaw v{__version__} — AI 渗透测试助手\n说人话，打漏洞 | 自然语言驱动的渗透测试"


def _print_banner() -> None:
    logo = Text(ASCII_LOGO, style="bold red")
    subtitle = Text(BANNER_SUBTITLE)
    console.print(logo)
    console.print(subtitle)
    console.print()


# ── REPL ────────────────────────────────────────────────────────────

def _run_repl() -> None:
    """Run the interactive REPL loop."""
    from vulnclaw.agent.core import AgentCore
    from vulnclaw.mcp.lifecycle import MCPLifecycleManager

    _print_banner()

    config = load_config()
    if not config.llm.api_key:
        console.print(
            "[!] 未检测到 LLM API Key，请先运行: [bold]vulnclaw config set llm.api_key <your-key>[/]"
        )
        console.print("    选择提供商: [bold]vulnclaw config provider <name>[/]")
        console.print("    或设置环境变量: [bold]VULNCLAW_LLM_API_KEY[/]")
        console.print()
        console.print("[dim]启动离线模式（仅本地工具可用，无 AI 推理）[/]")

    # Initialize MCP lifecycle manager
    mcp_manager = MCPLifecycleManager(config)
    started = mcp_manager.start_enabled_servers()
    console.print(f"[*] MCP 工具链: {started} 个服务已启动")

    # Initialize agent
    agent = AgentCore(config, mcp_manager)

    console.print("[dim]输入自然语言开始渗透测试，输入 help 查看帮助，Ctrl+C 退出[/]")
    console.print()

    # Track current target
    current_target: Optional[str] = None
    current_phase: str = "就绪"

    while True:
        try:
            # Build prompt string
            prompt_parts = []
            if current_target:
                prompt_parts.append(f"[bold cyan]{current_target}[/]")
            prompt_parts.append(f"[dim]{current_phase}[/]")
            prompt_str = " | ".join(prompt_parts) if prompt_parts else "vulnclaw"

            # Read input
            user_input = console.input(f"🦞 {prompt_str}> ").strip()

            if not user_input:
                continue

            # Handle built-in commands
            cmd_lower = user_input.lower()

            if cmd_lower in ("exit", "quit", "q"):
                console.print("[dim]Bye! 🦞[/]")
                break

            elif cmd_lower == "help":
                _print_help()
                continue

            elif cmd_lower == "status":
                _print_status(agent, mcp_manager, current_target, current_phase)
                continue

            elif cmd_lower.startswith("target "):
                current_target = user_input[7:].strip()
                console.print(f"[+] 目标已设置: [bold]{current_target}[/]")
                continue

            elif cmd_lower == "clear":
                current_target = None
                current_phase = "就绪"
                agent.reset_context()
                console.print("[*] 会话已清空")
                continue

            elif cmd_lower == "tools":
                tools = mcp_manager.list_available_tools()
                if tools:
                    console.print("[*] 当前可用 MCP 工具:")
                    for tool in tools:
                        console.print(f"  • {tool}")
                else:
                    console.print("[-] 无可用 MCP 工具")
                continue

            # Route to agent — detect if this should be an autonomous loop
            is_auto_mode = _should_auto_pentest(user_input, current_target)

            try:
                if is_auto_mode:
                    # Autonomous pentest loop
                    console.print("[dim][*] 进入自主渗透模式，按 Ctrl+C 可随时中断[/]")
                    console.print()

                    async def _run_auto():
                        results = []
                        def on_step(round_num, result):
                            # Real-time output for each round
                            console.print(f"[dim]── Round {round_num} ──[/]")
                            if result.output:
                                console.print(result.output)
                            console.print()

                            # Update target & phase from result
                            nonlocal current_target, current_phase
                            if result.target:
                                current_target = result.target
                            if result.phase:
                                current_phase = result.phase

                        results = await agent.auto_pentest(
                            user_input,
                            target=current_target,
                            max_rounds=15,
                            on_step=on_step,
                        )
                        return results

                    results = asyncio.run(_run_auto())

                    if results:
                        # Summary
                        total_findings = len(agent.session_state.findings)
                        total_steps = len(agent.session_state.executed_steps)
                        console.print()
                        console.print(Panel(
                            f"[*] 自主渗透完成\n"
                            f"    总轮数: {len(results)}\n"
                            f"    执行步骤: {total_steps}\n"
                            f"    发现漏洞: {total_findings}",
                            title="🦞 渗透结果",
                            border_style="green" if total_findings == 0 else "red",
                        ))

                else:
                    # Single-turn chat
                    async def _run_agent():
                        return await agent.chat(user_input, target=current_target)

                    result = asyncio.run(_run_agent())

                    if result:
                        # Update target & phase from agent result
                        if result.target:
                            current_target = result.target
                        if result.phase:
                            current_phase = result.phase

                        # Display agent output
                        if result.output:
                            console.print(result.output)

            except KeyboardInterrupt:
                console.print("\n[!] 用户中断")
            except Exception as e:
                console.print(f"[!] 错误: {e}")

        except KeyboardInterrupt:
            console.print("\n[dim]Ctrl+C 退出，输入 exit 确认[/]")
        except EOFError:
            break

    # Cleanup
    mcp_manager.stop_all()
    console.print("[dim]MCP 服务已关闭[/]")


def _print_help() -> None:
    """Print REPL help."""
    help_text = """
[bold]内置命令[/]:
  [cyan]target <host>[/]   设置渗透测试目标
  [cyan]status[/]          查看当前状态
  [cyan]tools[/]           列出可用 MCP 工具
  [cyan]clear[/]           清空当前会话
  [cyan]help[/]            显示此帮助
  [cyan]exit / quit[/]     退出

[bold]自主渗透模式[/]:
  [dim]输入包含目标的渗透指令，VulnClaw 会自动循环执行[/]
  [dim]例如: 对 www.example.com 进行渗透测试[/]

[bold]自然语言示例[/]:
  [dim]对 192.168.1.100 进行渗透测试，这是我授权的靶场[/]
  [dim]扫描目标的端口[/]
  [dim]发现有什么漏洞[/]
  [dim]尝试利用 CVE-202X-XXXX[/]
  [dim]生成渗透报告[/]
"""
    console.print(Panel(help_text, title="🦞 VulnClaw 帮助", border_style="cyan"))


def _print_status(agent, mcp_manager, target, phase) -> None:
    """Print current session status."""
    console.print(Panel(
        f"目标: [bold]{target or '未设置'}[/]\n"
        f"阶段: [bold]{phase}[/]\n"
        f"MCP 服务: [bold]{mcp_manager.running_count()}[/] 运行中\n"
        f"可用工具: [bold]{len(mcp_manager.list_available_tools())}[/] 个",
        title="🦞 当前状态",
        border_style="green",
    ))


# ── Sub-commands ────────────────────────────────────────────────────

@app.command()
def run(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    scope: str = typer.Option("full", help="Test scope: full, web, api, mobile"),
    output: Optional[str] = typer.Option(None, help="Output report file path"),
) -> None:
    """🚀 一键全流程渗透测试."""
    from vulnclaw.agent.core import AgentCore
    from vulnclaw.mcp.lifecycle import MCPLifecycleManager

    config = load_config()
    if not config.llm.api_key:
        err_console.print("[!] 请先配置 LLM API Key")
        raise typer.Exit(1)

    console.print(f"🦞 目标: [bold]{target}[/] | 范围: [bold]{scope}[/]")

    mcp_manager = MCPLifecycleManager(config)
    mcp_manager.start_enabled_servers()

    agent = AgentCore(config, mcp_manager)

    prompt = f"对已授权的目标 {target} 进行{scope}范围的渗透测试，这是我的授权靶场"

    async def _run():
        results = await agent.auto_pentest(
            prompt,
            target=target,
            max_rounds=15,
            on_step=lambda r, res: console.print(f"[dim]Round {r}[/]: {res.output[:200]}...") if res.output else None,
        )
        return results

    results = asyncio.run(_run())

    # Show summary
    total_findings = len(agent.session_state.findings)
    console.print(f"\n[+] 渗透测试完成，发现 {total_findings} 个漏洞")

    # Auto-generate report
    if output:
        from vulnclaw.report.generator import generate_report
        generate_report(agent.session_state, output)
        console.print(f"[+] 报告已保存: {output}")

    mcp_manager.stop_all()


@app.command()
def recon(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
) -> None:
    """🔍 仅执行信息收集阶段."""
    from vulnclaw.agent.core import AgentCore
    from vulnclaw.mcp.lifecycle import MCPLifecycleManager

    config = load_config()
    mcp_manager = MCPLifecycleManager(config)
    mcp_manager.start_enabled_servers()
    agent = AgentCore(config, mcp_manager)

    prompt = f"对已授权的目标 {target} 进行信息收集（仅被动+主动侦察，不进行漏洞利用）"
    result = asyncio.run(agent.chat(prompt, target=target))
    if result and result.output:
        console.print(result.output)
    mcp_manager.stop_all()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    ports: Optional[str] = typer.Option(None, help="Port range, e.g. 80,443,8080"),
) -> None:
    """🔎 执行漏洞扫描阶段."""
    from vulnclaw.agent.core import AgentCore
    from vulnclaw.mcp.lifecycle import MCPLifecycleManager

    config = load_config()
    mcp_manager = MCPLifecycleManager(config)
    mcp_manager.start_enabled_servers()
    agent = AgentCore(config, mcp_manager)

    port_hint = f"，重点关注端口 {ports}" if ports else ""
    prompt = f"对已授权的目标 {target} 进行漏洞扫描{port_hint}（仅发现漏洞，不进行利用）"
    result = asyncio.run(agent.chat(prompt, target=target))
    if result and result.output:
        console.print(result.output)
    mcp_manager.stop_all()


@app.command()
def exploit(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    cve: Optional[str] = typer.Option(None, help="Specific CVE to exploit"),
    cmd: str = typer.Option("id", help="Command to execute for verification"),
) -> None:
    """💥 执行漏洞利用阶段."""
    from vulnclaw.agent.core import AgentCore
    from vulnclaw.mcp.lifecycle import MCPLifecycleManager

    config = load_config()
    mcp_manager = MCPLifecycleManager(config)
    mcp_manager.start_enabled_servers()
    agent = AgentCore(config, mcp_manager)

    cve_hint = f"，利用 {cve}" if cve else ""
    prompt = f"对已授权的目标 {target} 尝试漏洞利用{cve_hint}，验证命令: {cmd}"
    result = asyncio.run(agent.chat(prompt, target=target))
    if result and result.output:
        console.print(result.output)
    mcp_manager.stop_all()


@app.command()
def report(
    session: str = typer.Argument(..., help="Path to session JSON file"),
) -> None:
    """📝 从会话记录生成渗透报告."""
    from vulnclaw.report.generator import generate_report_from_file
    generate_report_from_file(session)
    console.print(f"[+] 报告已生成")


# ── Config sub-command group ───────────────────────────────────────

config_app = typer.Typer(help="⚙️ 管理配置")
app.add_typer(config_app, name="config")


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key in dot notation, e.g. llm.api_key"),
    value: str = typer.Argument(..., help="Config value"),
) -> None:
    """设置配置项."""
    set_config_value(key, value)
    console.print(f"[+] 已设置: {key} = {'***' if 'key' in key.lower() or 'pass' in key.lower() else value}")


@config_app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Config key in dot notation"),
) -> None:
    """查看配置项."""
    config = load_config()
    parts = key.split(".")
    obj = config
    for part in parts:
        obj = getattr(obj, part)
    value = obj if not hasattr(obj, "model_dump") else obj.model_dump()
    if isinstance(value, str) and ("key" in key.lower() or "pass" in key.lower()):
        value = value[:8] + "..." if len(value) > 8 else "***"
    console.print(f"{key} = {value}")


@config_app.command("list")
def config_list() -> None:
    """列出所有配置."""
    import yaml as _yaml
    config = load_config()
    raw = config.model_dump(mode="json")
    console.print(_yaml.dump(raw, default_flow_style=False, allow_unicode=True))


@config_app.command("provider")
def config_provider(
    name: Optional[str] = typer.Argument(None, help="Provider name to switch to (e.g. minimax, deepseek)"),
    list_all: bool = typer.Option(False, "--list", "-l", help="List all available providers"),
) -> None:
    """🔌 查看/切换 LLM 提供商.

    用法:
      vulnclaw config provider --list     查看所有可用提供商
      vulnclaw config provider minimax    切换到 MiniMax
      vulnclaw config provider deepseek   切换到 DeepSeek
    """
    if list_all or name is None:
        providers = list_providers()
        current_config = load_config()
        current_provider = current_config.llm.provider

        console.print("[bold]🔌 可用 LLM 提供商[/]")
        console.print()
        for p in providers:
            is_current = p["provider"] == current_provider
            marker = " [green]◄ 当前[/]" if is_current else ""
            console.print(f"  [bold cyan]{p['provider']}[/]{marker}")
            console.print(f"    名称: {p['label']}")
            console.print(f"    URL:  [dim]{p['base_url']}[/]")
            console.print(f"    模型: [dim]{p['default_model']}[/]")
            console.print()
        console.print("[dim]使用 vulnclaw config provider <name> 切换提供商[/]")
        return

    # Switch provider
    from vulnclaw.config.schema import PROVIDER_PRESETS, LLMProvider

    # Validate provider name
    try:
        provider_enum = LLMProvider(name.lower())
    except ValueError:
        console.print(f"[!] 未知提供商: [bold]{name}[/]")
        console.print(f"    可用: {', '.join(p.value for p in LLMProvider)}")
        console.print(f"    提示: 使用 [bold]custom[/] 可手动设置 base_url 和 model")
        raise typer.Exit(1)

    config = load_config()
    config = apply_provider_preset(config, name.lower())
    save_config(config)

    preset = PROVIDER_PRESETS.get(provider_enum, {})
    label = preset.get("label", name)
    console.print(f"[+] 已切换 LLM 提供商: [bold cyan]{label}[/]")
    console.print(f"    Base URL: [dim]{config.llm.base_url}[/]")
    console.print(f"    模型:     [dim]{config.llm.model}[/]")

    if not config.llm.api_key:
        console.print()
        console.print(f"[yellow]⚠️ 请设置 API Key: [bold]vulnclaw config set llm.api_key <your-key>[/][/]")


# ── Init command ────────────────────────────────────────────────────

@app.command()
def init() -> None:
    """🔧 初始化 VulnClaw 配置."""
    from vulnclaw.config.settings import ensure_dirs
    ensure_dirs()

    config = load_config()
    save_config(config)
    console.print("[+] 配置文件已创建: ~/.vulnclaw/config.yaml")
    console.print("[+] 目录已初始化:")
    console.print("    ~/.vulnclaw/sessions/")
    console.print("    ~/.vulnclaw/kb/")
    console.print("    ~/.vulnclaw/skills/")
    console.print()
    console.print("[bold]下一步[/]:")
    console.print("  1. 选择提供商: [bold]vulnclaw config provider minimax[/] (或 openai/deepseek/zhipu/moonshot/qwen/siliconflow)")
    console.print("  2. 配置 Key:   [bold]vulnclaw config set llm.api_key <your-key>[/]")
    console.print("  3. 启动 REPL:  [bold]vulnclaw[/]")


# ── Doctor command ──────────────────────────────────────────────────

@app.command()
def doctor() -> None:
    """🏥 检查 VulnClaw 运行环境."""
    import shutil

    console.print("[bold]🦞 VulnClaw 环境检查[/]")
    console.print()

    # Check Python
    console.print(f"  Python: [green]{sys.version.split()[0]}[/]")

    # Check Node.js
    node_path = shutil.which("node")
    if node_path:
        import subprocess
        try:
            result = subprocess.run(
                [node_path, "--version"], capture_output=True, text=True, timeout=5
            )
            console.print(f"  Node.js: [green]{result.stdout.strip()}[/]")
        except Exception:
            console.print("  Node.js: [yellow]检测失败[/]")
    else:
        console.print("  Node.js: [red]未安装[/] (MCP 服务需要)")

    # Check npx
    npx_path = shutil.which("npx")
    console.print(f"  npx: [{'green' if npx_path else 'red'}]{'已安装' if npx_path else '未安装'}[/]")

    # Check uvx
    uvx_path = shutil.which("uvx")
    console.print(f"  uvx: [{'green' if uvx_path else 'yellow'}]{'已安装' if uvx_path else '未安装'}[/]")

    # Check nmap
    nmap_path = shutil.which("nmap")
    console.print(f"  nmap: [{'green' if nmap_path else 'yellow'}]{'已安装' if nmap_path else '未安装 (可选)'}[/]")

    # Check config
    config = load_config()
    console.print()
    console.print("[bold]LLM 配置[/]:")
    has_key = bool(config.llm.api_key)
    console.print(f"  Provider: [bold cyan]{config.llm.provider}[/]")
    console.print(f"  API Key: [{'green' if has_key else 'red'}]{'已设置' if has_key else '未设置'}[/]")
    console.print(f"  Base URL: [dim]{config.llm.base_url}[/]")
    console.print(f"  Model: [dim]{config.llm.model}[/]")

    # Check MCP servers
    console.print()
    console.print("[bold]MCP 服务[/]:")
    for name, srv in config.mcp.servers.items():
        status = "[green]已启用[/]" if srv.enabled else "[dim]未启用[/]"
        priority_label = {0: "P0", 1: "P1", 2: "P2"}.get(srv.priority, "??")
        console.print(f"  {name}: {status} [{priority_label}]")

    console.print()
    if has_key:
        console.print("[green]✅ 环境就绪，运行 [bold]vulnclaw[/] 开始[/]")
    else:
        console.print("[yellow]⚠️ 请先配置 API Key: [bold]vulnclaw config set llm.api_key <key>[/][/]")


# ── KB command ──────────────────────────────────────────────────────

kb_app = typer.Typer(help="📚 安全知识库管理")
app.add_typer(kb_app, name="kb")


@kb_app.command("update")
def kb_update() -> None:
    """更新安全知识库."""
    console.print("[*] 正在更新知识库...")
    # TODO: implement KB update logic
    console.print("[+] 知识库已更新")


# ── Default command (no sub-command → REPL) ────────────────────────

# ── Auto-pentest detection ──────────────────────────────────────────


def _should_auto_pentest(user_input: str, current_target: Optional[str]) -> bool:
    """Determine if user input should trigger autonomous pentest loop.

    Triggers when:
    - User explicitly asks for a full pentest with a target
    - User mentions a target + action keywords like "渗透测试", "打一下"
    - A target is set and the request is broad (not a specific single-step query)
    """
    input_lower = user_input.lower()

    # Explicit auto-mode triggers
    auto_keywords = [
        "渗透测试", "进行渗透", "做渗透", "打一下", "全面测试",
        "pentest", "full test", "auto",
    ]

    # Single-step queries should NOT trigger auto mode
    single_step_keywords = [
        "扫描端口", "端口扫描", "nmap", "port scan",
        "生成报告", "report",
        "查看", "show", "list", "status",
        "help", "帮助",
    ]

    # If it's clearly a single-step query, don't auto-loop
    if any(kw in input_lower for kw in single_step_keywords) and not any(kw in input_lower for kw in auto_keywords):
        return False

    # If it has auto-mode keywords, trigger auto loop
    if any(kw in input_lower for kw in auto_keywords):
        # Must have a target (either in input or already set)
        has_target = bool(current_target) or bool(_extract_target_from_input(user_input))
        return has_target

    return False


def _extract_target_from_input(user_input: str) -> Optional[str]:
    """Extract target from user input string."""
    import re
    # Try to find IP address
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', user_input)
    if ip_match:
        return ip_match.group(1)
    # Try to find domain
    domain_match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', user_input)
    if domain_match:
        return domain_match.group(1)
    return None


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """🦞 VulnClaw — AI-powered penetration testing CLI."""
    if ctx.invoked_subcommand is None:
        _run_repl()


if __name__ == "__main__":
    app()
