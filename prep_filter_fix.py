"""Check the <think> patterns more carefully."""
with open(r'c:\Users\UncleC\Desktop\VulnClaw\vulnclaw\report\filter.py', 'r', encoding='utf-8') as f:
    content = f.read()

lines = content.split('\n')
in_think = False
think_section_lines = []
for i, line in enumerate(lines):
    if 'THINK_PATTERNS' in line:
        in_think = True
    if in_think:
        think_section_lines.append((i+1, line))
        if 'PYTHON_CODE_PATTERNS' in line:
            break

print('THINK_PATTERNS section:')
for lineno, line in think_section_lines:
    print(f'  L{lineno}: {repr(line)}')
    # Also print the actual characters for each line
    chars = [(j, c, U+ord(c) if hasattr(c, '__int__') else ord(c)) for j, c in enumerate(line)]
