# ECC 攻击速查表

## 椭圆曲线基础

```python
# 椭圆曲线: y² = x³ + ax + b (mod p)
# 点运算: P + Q, k*P
# ECDLP: 已知 P, Q=k*P，求 k
```

## 攻击选择

| 条件 | 攻击方法 | 适用场景 |
|------|---------|---------|
| 阶 n 是光滑数 | Pohlig-Hellman | n 的因子都小 |
| 曲线异常 (p=n) | Smart 攻击 | 异常曲线 |
| 子群阶小 | 小子群攻击 | 阶有大素因子 |
| 曲线参数可疑 | Invalid Curve 攻击 | 非标准曲线 |
| ECDSA nonce 重用 | 确定性攻击 | 同一 k 签两次 |
| 阶很小 | 暴力/Baby-step Giant-step | n < 2^40 |

## Pohlig-Hellman 攻击

```python
# Sage 实现
# 当群阶 n 的因子都较小时

P = EllipticCurve(GF(p), [a, b])
G = P(P_x, P_y)  # 基点
Q = P(Q_x, Q_y)  # 目标点

n = P.order()  # 群阶
factors = factor(n)

# Pohlig-Hellman
k = discrete_log(Q, G, operation='+')
# 或指定方法
k = Q.discrete_log(G)
```

## Smart 攻击 (异常曲线)

```python
# 当曲线的阶等于特征 p (异常曲线)
# E.lift_x() 可能失败但可以利用 p-adic 提升

# Sage 实现
def smart_attack(P, Q, p, a, b):
    """Smart 攻击，适用于 #E = p 的异常曲线"""
    E = EllipticCurve(Qp(p), [a, b])
    P_lift = E.lift_x(ZZ(P.xy()[0]))
    Q_lift = E.lift_x(ZZ(Q.xy()[0]))
    
    pP = p * P_lift
    pQ = p * Q_lift
    
    x1 = pP.xy()[0] / pP.xy()[1]
    x2 = pQ.xy()[0] / pQ.xy()[1]
    
    k = ZZ(x2) / ZZ(x1) % p
    return k
```

## Invalid Curve 攻击

```python
# 当服务器不验证点是否在曲线上
# 可以发送不在曲线上的点，该点可能在另一条曲线上
# 如果那条曲线的阶是光滑的，可以用 Pohlig-Hellman

# 构造：选择 a' 使得 y² = x³ + a'*x + b 有光滑阶
```

## ECDSA Nonce 重用攻击

```python
"""
如果 ECDSA 中同一个 nonce k 被用于两次签名：
s1 = k^(-1) * (h1 + r*d) mod n
s2 = k^(-1) * (h2 + r*d) mod n

s1 - s2 = k^(-1) * (h1 - h2) mod n
k = (h1 - h2) * (s1 - s2)^(-1) mod n
d = (s1 * k - h1) * r^(-1) mod n  (私钥)
"""

def ecdsa_nonce_reuse(r1, s1, h1, r2, s2, h2, n):
    """ECDSA nonce 重用恢复私钥"""
    from gmpy2 import invert
    # 确认 r 相同
    assert r1 == r2
    k = ((h1 - h2) * invert(s1 - s2, n)) % n
    d = ((s1 * k - h1) * invert(r1, n)) % n
    return int(d)
```

## 常见 ECC CTF 题型

| 题型 | 特征 | 攻击 |
|------|------|------|
| 标准曲线 + 小阶 | n < 2^40 | 暴力 |
| 标准曲线 + 光滑阶 | n 有小因子 | Pohlig-Hellman |
| 异常曲线 | #E = p | Smart 攻击 |
| 自定义曲线 | a, b 可疑 | Invalid Curve / 分解阶 |
| ECDSA 签名 | 多组签名 | Nonce 重用 |
| Twisted Edwards | x² + a*y² = 1 + d*x²*y² | 转换为 Weierstrass |
