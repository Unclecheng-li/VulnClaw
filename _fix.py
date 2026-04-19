"""One-time script to fix think tag handling in core.py."""
import re

with open('vulnclaw/agent/core.py', 'r', encoding='utf-8') as f:
    content = f.read()

# === PART 1: Replace think tag patterns and functions ===
# Find the exact line range of the think section
start_mark = '# ▶ Think tag filtering ▶'
end_mark = '`@dataclass'

# Find the start of the think section
start_idx = content.find(start_mark)
# Find the end of format_think_tags function (before @dataclass)
end_idx = content.find(end_mark, start_idx)

print(f"Found think section: {start_idx}:{end_idx}")

print(repr(content[start_idx:start_idx+200]))
