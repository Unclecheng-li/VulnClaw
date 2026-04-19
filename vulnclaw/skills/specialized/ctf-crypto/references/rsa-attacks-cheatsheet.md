# RSA 攻击速查表

## 攻击选择决策树

```
已知 n, e, c
├── e 很小 (e=3)?
│   ├── 同一明文多次加密 (多组c)? → Håstad 广播攻击
│   └── 只有一组? → 小指数开根攻击 (低概率)
├── 多组 (n, e, c)?
│   ├── n 相同? → 共模攻击
│   ├── e 相同? → Håstad 广播攻击
│   └── p 或 q 有公因子? → GCD 分解
├── e 很大 (>65537)?
│   └── d 可能很小 → Wiener 攻击
├── n 可分解?
│   ├── Fermat 分解 (p≈q)
│   ├── Pollard p-1 (p-1 因子小)
│   ├── Williams p+1 (p+1 因子小)
│   └── 在线查询 (factordb)
└── 已知部分信息?
    ├── 部分明文 → Coppersmith
    ├── 部分p → Coppersmith
    └── 部分d → 直接构造
```

## 小指数攻击 (e=3)

### 低指数广播攻击 (Håstad)
```python
from gmpy2 import iroot
from functools import reduce

def hastard_broadcast(cs, ns, e=3):
    """当同一明文被 e 组不同 n 加密时"""
    # CRT 求解
    N = reduce(lambda a, b: a * b, ns)
    x = 0
    for i in range(e):
        Mi = N // ns[i]
        yi = pow(Mi, -1, ns[i])
        x += cs[i] * Mi * yi
    x %= N
    m = iroot(x, e)
    if m[1]:
        return int(m[0])
    return None
```

## 共模攻击

```python
from gmpy2 import gcd

def common_modulus_attack(c1, c2, e1, e2, n):
    """同一明文、同一n、不同e加密"""
    g, s1, s2 = extended_gcd(e1, e2)
    if s1 < 0:
        c1 = pow(c1, -1, n)
        s1 = -s1
    if s2 < 0:
        c2 = pow(c2, -1, n)
        s2 = -s2
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x
```

## Wiener 攻击 (e 很大, d 很小)

```python
def wiener_attack(e, n):
    """当 d < n^(1/4) 时有效"""
    cf = continued_fraction(e, n)
    convergents = get_convergents(cf)
    for k, d in convergents:
        if k == 0:
            continue
        phi = (e * d - 1) // k
        # 检查是否是有效的 phi
        x = n - phi + 1
        disc = x * x - 4 * n
        if disc >= 0:
            s = int(disc ** 0.5)
            if s * s == disc:
                return d
    return None
```

## Fermat 分解 (p ≈ q)

```python
from gmpy2 import is_square, iroot

def fermat_factor(n):
    """当 p 和 q 很接近时有效"""
    a = iroot(n, 2)[0] + 1
    b2 = a * a - n
    while not is_square(b2):
        a += 1
        b2 = a * a - n
    p = a + iroot(b2, 2)[0]
    q = a - iroot(b2, 2)[0]
    return int(p), int(q)
```

## Pollard p-1 攻击

```python
from math import gcd

def pollard_p1(n, B=100000):
    """当 p-1 的因子都小于 B 时有效"""
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d, n // d
    return None
```

## Coppersmith 攻击 (已知部分明文)

```python
# 使用 SageMath
# 当已知明文的高位或低位时
# m = known_part + unknown_part
# unknown_part < n^(1/e)

# Sage 实现：
P.<x> = PolynomialRing(Zmod(n))
f = (known_prefix + x)^e - c
f = f.monic()
roots = f.small_roots()
if roots:
    m = known_prefix + roots[0]
```

## 在线分解工具

- https://factordb.com — 查询已分解的 n
- http://sagecell.sagemath.org — 在线 Sage 计算
