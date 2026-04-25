"""Think filter regression tests."""

import pytest

from vulnclaw.agent.core import AgentCore
from vulnclaw.agent.think_filter import format_think_tags, strip_think_tags


class _FakeMessage:
    def __init__(self, content: str = "", reasoning_content: str | None = None):
        self.content = content
        self.reasoning_content = reasoning_content


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("<thinking>some reasoning</thinking>actual response", "actual response"),
        ("<thinking>some reasoning that never closes\nmore thinking", ""),
        ("<thinking>reasoning\nactual response", ""),
        ("<thinking>first</thinking>middle<thinking>second</thinking>end", "middleend"),
        ("just a normal response", "just a normal response"),
        ("<thinking>closed</thinking>answer<thinking>unclosed", "answer"),
        ("<reasoning>internal</reasoning>final answer", "final answer"),
    ],
)
def test_strip_think_tags(text: str, expected: str):
    assert strip_think_tags(text) == expected


@pytest.mark.parametrize(
    ("text", "show", "expected"),
    [
        ("<thinking>abc</thinking>answer", True, "<thinking>abc</thinking>answer"),
        ("<thinking>abc</thinking>answer", False, "answer"),
        ("just a normal response", True, "just a normal response"),
        ("just a normal response", False, "just a normal response"),
        ("<thinking>only thinking", False, ""),
    ],
)
def test_format_think_tags(text: str, show: bool, expected: str):
    assert format_think_tags(text, show=show) == expected


def test_extract_response_wraps_reasoning_only_message():
    message = _FakeMessage(content="", reasoning_content="I am thinking deeply")
    response = AgentCore._extract_response(message)

    assert "<thinking>" in response
    assert "I am thinking deeply" in response
    assert format_think_tags(response, show=False) == ""


def test_extract_response_wraps_reasoning_and_answer():
    message = _FakeMessage(content="actual answer", reasoning_content="my reasoning")
    response = AgentCore._extract_response(message)

    assert "<thinking>" in response
    assert "my reasoning" in response
    assert "actual answer" in response
    assert format_think_tags(response, show=False) == "actual answer"


def test_extract_response_plain_message_unchanged():
    message = _FakeMessage(content="hello world", reasoning_content=None)
    assert AgentCore._extract_response(message) == "hello world"
