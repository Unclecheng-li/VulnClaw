"""Test the fixed think tag handling."""
from vulnclaw.agent.core import strip_think_tags, format_think_tags

# Test 1: Closed thinking tag
t1 = "<thinking>some reasoning</thinking>actual response"
r1_strip = strip_think_tags(t1)
r1_hide = format_think_tags(t1, show=False)
print(f"Test 1 (closed): strip={r1_strip!r}, hide={r1_hide!r}")
assert r1_strip == "actual response", f"FAIL: {r1_strip}"
assert r1_hide == "actual response", f"FAIL: {r1_hide}"

# Test 2: UNCLOSED thinking tag (THE BUG)
t2 = "<thinking>some reasoning that never closes\nmore thinking"
r2_strip = strip_think_tags(t2)
r2_hide = format_think_tags(t2, show=False)
print(f"Test 2 (unclosed): strip={r2_strip!r}, hide={r2_hide!r}")
assert r2_strip == "", f"FAIL: expected empty, got {r2_strip}"
assert r2_hide == "", f"FAIL: expected empty, got {r2_hide}"

# Test 3: Unclosed thinking eats everything after it
t3 = "<thinking>reasoning\nactual response"
r3_strip = strip_think_tags(t3)
print(f"Test 3 (unclosed+content): strip={r3_strip!r}")
assert r3_strip == "", f"FAIL: expected empty since unclosed eats all, got {r3_strip}"

# Test 4: Multiple closed tags
t4 = "<thinking>first</thinking>middle<thinking>second</thinking>end"
r4_strip = strip_think_tags(t4)
r4_hide = format_think_tags(t4, show=False)
print(f"Test 4 (multi-closed): strip={r4_strip!r}")
assert r4_strip == "middleend", f"FAIL: {r4_strip}"

# Test 5: No thinking tags
t5 = "just a normal response"
r5_strip = strip_think_tags(t5)
r5_hide = format_think_tags(t5, show=False)
print(f"Test 5 (no tags): strip={r5_strip!r}")
assert r5_strip == "just a normal response", f"FAIL: {r5_strip}"

# Test 6: Real-world DeepSeek R1 output (unclosed + no answer)
t6 = (
    "<thinking>\u6e90\u7801\u8fd8\u662f\u88ab\u622a\u65ad\u4e86\uff0c\u53ea\u6709 3 \u884c\u3002"
    "\u53ef\u80fd\u9875\u9762\u6709\u66f4\u591a\u5185\u5bb9\uff0c\u6216\u8005\u6e90\u7801\u4e2d\u6709\u4e9b\u90e8\u5206\u5728\u6ce8\u91ca\u540e\u9762\uff1f"
    "\u8ba9\u6211\u8bd5\u8bd5\u76f4\u63a5\u8bbf\u95ee\u67e5\u770b\u6e90\u7801\u7684\u7aef\u70b9\uff0c\u6216\u8005\u5c1d\u8bd5\u5176\u4ed6\u65b9\u6cd5\u3002"
)
r6_strip = strip_think_tags(t6)
r6_hide = format_think_tags(t6, show=False)
r6_show = format_think_tags(t6, show=True)
is_empty = r6_strip == ""
has_dim = "[dim]" in r6_show
print(f"Test 6 (real DeepSeek): strip_empty={is_empty}, hide_empty={r6_hide == ''}, has_dim={has_dim}")
assert is_empty, f"FAIL: expected empty, got {r6_strip[:50]}"
assert r6_hide == "", f"FAIL: expected empty, got {r6_hide[:50]}"
assert has_dim, "FAIL: no dim markup in show mode"

# Test 7: Closed thinking with actual response after
t7 = "<thinking>\u8ba9\u6211\u5206\u6790\u4e00\u4e0b\u8fd9\u4e2a\u95ee\u9898</thinking>\n\u7b54\u6848\u662f 42"
r7_strip = strip_think_tags(t7)
r7_hide = format_think_tags(t7, show=False)
r7_show = format_think_tags(t7, show=True)
print(f"Test 7 (closed+answer): strip={r7_strip!r}, hide={r7_hide!r}")
assert "\u7b54\u6848\u662f 42" in r7_strip, f"FAIL: answer lost: {r7_strip}"
assert "\u7b54\u6848\u662f 42" in r7_hide, f"FAIL: answer lost: {r7_hide}"
assert "[dim]" in r7_show, "FAIL: thinking not dimmed in show mode"
assert "\u7b54\u6848\u662f 42" in r7_show, f"FAIL: answer lost in show mode"

# Test 8: _extract_response with reasoning_content
from vulnclaw.agent.core import AgentCore

class FakeMessage:
    def __init__(self, content, reasoning_content=None):
        self.content = content
        self.reasoning_content = reasoning_content

# Normal message
msg1 = FakeMessage("hello world")
r8a = AgentCore._extract_response(msg1)
print(f"Test 8a (normal): {r8a!r}")
assert r8a == "hello world"

# Message with reasoning_content only
msg2 = FakeMessage("", "I am thinking deeply")
r8b = AgentCore._extract_response(msg2)
print(f"Test 8b (reasoning_only): has_thinking_tag={'<thinking>' in r8b}, has_content={'I am thinking deeply' in r8b}")
assert "<thinking>" in r8b, "FAIL: no thinking tag for reasoning_content"
assert "I am thinking deeply" in r8b, "FAIL: reasoning content lost"

# Message with both
msg3 = FakeMessage("actual answer", "my reasoning")
r8c = AgentCore._extract_response(msg3)
print(f"Test 8c (both): has_thinking={'<thinking>' in r8c}, has_answer={'actual answer' in r8c}")
assert "<thinking>" in r8c, "FAIL: no thinking tag"
assert "my reasoning" in r8c, "FAIL: reasoning lost"
assert "actual answer" in r8c, "FAIL: answer lost"

# Message with None reasoning_content
msg4 = FakeMessage("hello", None)
r8d = AgentCore._extract_response(msg4)
print(f"Test 8d (none_reasoning): {r8d!r}")
assert r8d == "hello", f"FAIL: {r8d}"

print()
print("ALL TESTS PASSED!")
