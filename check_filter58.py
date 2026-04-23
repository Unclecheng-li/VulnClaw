"""Check line 58 raw bytes to confirm it's correct."""
f = open(r'c:\Users\UncleC\Desktop\VulnClaw\vulnclaw\report\filter.py', 'rb')
data = f.read()
f.close()

lines = data.split(b'\n')
line58 = lines[57]  # 0-indexed
print('Line 58 raw:', repr(line58))
print('Line 58 decoded:', line58.decode('utf-8', errors='replace'))

# Check for key bytes
if b'<reasoning' in line58:
    print('Contains: <reasoning')
elif b'\x3c\x72\x65\x61\x73\x6f\x6e\x69\x6e\x67' in line58:
    print('Contains: <reasoning (as ASCII bytes)')
else:
    print('Does NOT contain <reasoning as expected')
