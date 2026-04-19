"""Test think tag handling after the fix."""
import sys
sys.path.insert(0, ".")

from vulnclaw.agent.core import strip_think_tags, format_think_tags

# Test 1: Closed thinking tag
t1 = "<thinking>some reasoning</thinking>actual response"
r1_strip = strip_think_tags(t1)
r1_show = format_think_tags(t1, show=True)
r1_hide = format_think_tags(t1, show=False)
assert r1_strip == "actual response", f"FAIL strip: {r1_strip!r}"
assert r1_hide == "actual response", f"FAIL hide: {r1_hide!r}"
assert r1_show == t1, f"FAIL show: show=True should return original"
print("PASS Test 1: Closed thinking tag")

# Test 2: UNCLOSED thinking tag
t2 = "<thinking>some reasoning that never closes\nmore thinking"
r2_strip = strip_think_tags(t2)
r2_show = format_think_tags(t2, show=True)
r2_hide = format_think_tags(t2, show=False)
assert r2_strip == "", f"FAIL strip: {r2_strip!r}"
assert r2_hide == "", f"FAIL hide: {r2_hide!r}"
assert r2_show == t2, f"FAIL show: show=True should return original"
print("PASS Test 2: Unclosed thinking tag")

# Test 3: No thinking tags
t3 = "just a normal response"
r3_strip = strip_think_tags(t3)
r3_show = format_think_tags(t3, show=True)
r3_hide = format_think_tags(t3, show=False)
assert r3_strip == "just a normal response", f"FAIL strip: {r3_strip!r}"
assert r3_show == t3, f"FAIL show: {r3_show!r}"
assert r3_hide == "just a normal response", f"FAIL hide: {r3_hide!r}"
print("PASS Test 3: No thinking tags")

# Test 4: Multiple closed tags
t4 = "<thinking>first</thinking>middle<thinking>second</thinking>end"
r4_strip = strip_think_tags(t4)
r4_hide = format_think_tags(t4, show=False)
r4_show = format_think_tags(t4, show=True)
assert r4_strip == "middleend", f"FAIL strip: {r4_strip!r}"
assert r4_hide == "middleend", f"FAIL hide: {r4_hide!r}"
assert r4_show == t4, f"FAIL show: {r4_show!r}"
print("PASS Test 4: Multiple closed tags")

# Test 5: Real-world DeepSeek R1 output (unclosed + no answer)
t5 = "<thinking>\u6e90\u7801\u8fd8\u662f\u88ab\u622a\u65ad\u4e86\uff0c\u53ea\u6709 3 \u884c\u3002\u53ef\u80fd\u9875\u9762\u6709\u66f4\u591a\u5185\u5bb9\n\n\u8ba9\u6211\u8bd5\u8bd5\u770b\u80fd\u4e0d\u80fd\u8bbf\u95ee highlight_file"
r5_strip = strip_think_tags(t5)
r5_hide = format_think_tags(t5, show=False)
r5_show = format_think_tags(t5, show=True)
assert r5_strip == "", f"FAIL strip: {r5_strip!r}"
assert r5_hide == "", f"FAIL hide: {r5_hide!r}"
assert r5_show == t5, f"FAIL show: show=True should return original text"
print("PASS Test 5: Real DeepSeek unclosed output")

# Test 6: reasoning_content from _extract_response
from vulnclaw.agent.core import AgentCore

class FakeMessage:
    content = "actual answer"
    reasoning_content = "thinking text"

r6 = AgentCore._extract_response(FakeMessage())
assert "<thinking>" in r6, f"FAIL: reasoning_content not wrapped: {r6!r}"
assert "thinking text" in r6, f"FAIL: thinking text missing: {r6!r}"
assert "actual answer" in r6, f"FAIL: actual answer missing: {r6!r}"

r6_show = format_think_tags(r6, show=True)
assert r6_show == r6, f"FAIL show: {r6_show!r} != {r6!r}"

r6_hide = format_think_tags(r6, show=False)
assert r6_hide == "actual answer", f"FAIL hide: {r6_hide!r}"
print("PASS Test 6: reasoning_content extraction")

# Test 7: reasoning_content with empty content
class FakeMessage2:
    content = ""
    reasoning_content = "only thinking, no answer"

r7 = AgentCore._extract_response(FakeMessage2())
assert "<thinking>" in r7, f"FAIL: reasoning_content not wrapped: {r7!r}"

r7_hide = format_think_tags(r7, show=False)
assert r7_hide == "", f"FAIL hide: expected empty, got {r7_hide!r}"

r7_show = format_think_tags(r7, show=True)
assert r7_show == r7, f"FAIL show: {r7_show!r} != {r7!r}"
print("PASS Test 7: reasoning_content only, no answer")

# Test 8: Closed + unclosed mix
t8 = "<thinking>closed</thinking>answer<thinking>unclosed"
r8_strip = strip_think_tags(t8)
r8_show = format_think_tags(t8, show=True)
r8_hide = format_think_tags(t8, show=False)
assert r8_strip == "answer", f"FAIL strip: {r8_strip!r}"
assert r8_show == t8, f"FAIL show: {r8_show!r}"
assert r8_hide == "answer", f"FAIL hide: {r8_hide!r}"
print("PASS Test 8: Closed + unclosed mix")

# Test 9: Key behavior - show=True returns EXACTLY the original text
t9 = "<thinking>Line1\nLine2\nLine3</thinking>Real answer here"
r9_show = format_think_tags(t9, show=True)
assert r9_show == t9, f"FAIL: show=True must return original text unchanged"
r9_hide = format_think_tags(t9, show=False)
assert r9_hide == "Real answer here", f"FAIL hide: {r9_hide!r}"
print("PASS Test 9: show=True preserves original text exactly")

print("\n=== ALL 9 TESTS PASSED ===")
