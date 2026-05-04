"""VulnClaw basic integration tests — verify package-level imports and version."""

import pytest


def test_import_vulnclaw():
    """Test that the main package can be imported."""
    import vulnclaw
    assert vulnclaw.__version__ == "0.2.6"


def test_all_submodules_importable():
    """Test that all submodules can be imported."""
    import vulnclaw.config.schema
    import vulnclaw.config.settings
    import vulnclaw.agent.context
    import vulnclaw.agent.memory
    import vulnclaw.agent.prompts
    import vulnclaw.agent.core
    import vulnclaw.mcp.registry
    import vulnclaw.mcp.router
    import vulnclaw.mcp.lifecycle
    import vulnclaw.skills.loader
    import vulnclaw.skills.dispatcher
    import vulnclaw.kb.store
    import vulnclaw.kb.retriever
    import vulnclaw.kb.updater
    import vulnclaw.report.generator
    import vulnclaw.report.poc_builder


def test_no_import_errors():
    """Verify no module raises on import."""
    import importlib
    modules = [
        "vulnclaw",
        "vulnclaw.config.schema",
        "vulnclaw.config.settings",
        "vulnclaw.agent.context",
        "vulnclaw.agent.memory",
        "vulnclaw.agent.prompts",
        "vulnclaw.agent.core",
        "vulnclaw.mcp.registry",
        "vulnclaw.mcp.router",
        "vulnclaw.mcp.lifecycle",
        "vulnclaw.skills.loader",
        "vulnclaw.skills.dispatcher",
        "vulnclaw.kb.store",
        "vulnclaw.kb.retriever",
        "vulnclaw.kb.updater",
        "vulnclaw.report.generator",
        "vulnclaw.report.poc_builder",
        "vulnclaw.cli.main",
    ]
    for mod_name in modules:
        try:
            importlib.import_module(mod_name)
        except ImportError as e:
            pytest.fail(f"Failed to import {mod_name}: {e}")
