# 编码链识别与解码

## 编码识别特征

| 编码 | 特征 | 示例 |
|------|------|------|
| Base64 | `A-Za-z0-9+/=`, 长度 % 4 | `TnNTY1RmLnBocA==` |
| Base32 | `A-Z2-7=`, 长度 % 8 | `OBZHK5DFN2A====` |
| Base16 | `0-9A-F`, 偶数长度 | `4E535354662E706870` |
| URL 编码 | `%XX` | `%2F%61%64%6D%69%6E` |
| HTML 实体 | `&#xNNN;` 或 `&#NNN;` | `&#x3C;script&#x3E;` |
| Unicode | `\uXXXX` 或 `\UXXXXXXXX` | `\u003c\u0073\u0063` |
| Hex (Python) | `\xNN` | `\x4e\x53\x53\x54` |
| ROT13 | 字母替换，Caesar | `axzc` → `nmp` |
| Morse | `.` `-` `/` 组合 | `.-/-.../-.-.` |
| Binary | `01` 数组 | `01001101` |

## 常见编码链

### 1. 简单链
```
Hex → Base64 → URL编码
```

### 2. 二进制系
```
Binary → ASCII
Octal → ASCII
Hex → ASCII
```

### 3. 浏览器系
```
HTML实体 → URL编码 → Base64
```

### 4. 特殊编码
```
Brainfuck (`><+-.,[]`)
Ook! (`Ook. Ook?`)
Hex → Ook! → Brainfuck
```

## 自动解码脚本

```python
import base64, binascii, urllib.parse, html

def auto_decode(data, max_iter=10):
    """自动尝试多层解码"""
    result = data
    for _ in range(max_iter):
        changed = False
        original = result

        # URL decode
        try:
            result = urllib.parse.unquote(result)
            if result != original:
                changed = True
        except:
            pass

        # HTML entity decode
        try:
            result = html.unescape(result)
            if result != original:
                changed = True
        except:
            pass

        # Base64 decode
        try:
            result = base64.b64decode(result).decode('utf-8')
            if result != original:
                changed = True
        except:
            try:
                result = base64.b64decode(result + '==').decode('utf-8')
                if result != original:
                    changed = True
            except:
                pass

        # Hex decode
        try:
            if all(c in '0123456789abcdefABCDEF' for c in result.replace('%', '')):
                result = bytes.fromhex(result.replace('%', '')).decode('utf-8')
                if result != original:
                    changed = True
        except:
            pass

        # ROT13
        try:
            result = original.encode().translate(bytes.maketrans(
                b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                b'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            )).decode()
            if result != original:
                changed = True
        except:
            pass

        if not changed:
            break

    return result
```

## 二维码解码

```python
from PIL import Image
import zbarlight

def decode_qr(image_path):
    """解码 QR 码"""
    image = Image.open(image_path)
    codes = zbarlight.scan_codes(['qrcode'], image)
    return codes
```

## 音频隐写 (最低有效位)

```python
def extract_lsb_wav(wav_path):
    """从 WAV 提取 LSB 隐写数据"""
    import wave, struct
    with wave.open(wav_path, 'rb') as wav:
        frames = wav.readframes(wav.getnframes())
        binary = ''
        for byte in frames:
            binary += str(byte & 1)
    # 每 8 位一个字符
    result = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:
            result += chr(int(byte, 2))
    return result
```

## 图片隐写

```python
from PIL import Image

def extract_lsb_png(image_path):
    """从 PNG 提取 LSB 隐写"""
    img = Image.open(image_path)
    pixels = list(img.getdata())
    binary = ''
    for pixel in pixels:
        if isinstance(pixel, tuple):
            for channel in pixel[:3]:
                binary += str(channel & 1)
        else:
            binary += str(pixel & 1)
    # 每 8 位一个字符
    result = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:
            result += chr(int(byte, 2))
    return result
```
