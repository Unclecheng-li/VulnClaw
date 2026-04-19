# 格攻击与 LWE

## 基础概念

```
格 (Lattice): Z^n 中的离散加法子群
格基 (Basis): 生成格的线性无关向量组
LLL 算法: 求格基的近似最短向量 (SVP 近似)
CVP (Closest Vector Problem): 找最近向量
SVP (Shortest Vector Problem): 找最短向量
```

## LLL 算法

```python
# SageMath 实现
"""
A = matrix(ZZ, [[...], [...], ...])  # 格基矩阵
B = A.LLL()  # LLL 规约基
# B 的列向量是接近最短的格向量
```

## Hidden Number Problem (HNP)

```python
"""
已知: (d_i, (t_i * a + k_i * d_i) mod p) 部分位
恢复: a (私钥)
利用 Coppersmith 求出 k_i
"""
# SageMath
def hnp_attack(d, t, bits, p):
    F.<x> = PolynomialRing(Zmod(p))
    # 构造多项式...
```

## Coppersmith 相关

```python
"""
Coppersmith 求多项式小根：
f(x) = 0 mod n, |x| < n^(1/d)
其中 d 是多项式次数
"""

# SageMath
def coppersmith_small_root(f, n, d, m):
    """f(x) = 0 mod n, 求小根 x, |x| < n^(1/(d*omega))"""
    # 构造格并 LLL
```

## LWE (Learning With Errors)

```python
"""
LWE 问题：
已知: (A, b = As + e) mod q
恢复: s (私钥)
其中 e 是小误差向量

常用攻击:
1. 枚举小误差 (e 很小时)
2. BKW 算法
3. 规约到 SVP/CVP
"""
```

## HNP 攻击模板

```python
# SageMath: 从部分私钥恢复 RSA 私钥
"""
DCP (Diffie-Hellman Claw Problem) 变种
利用格规约求解
"""

# 基本模板
"""
F = GF(p)
P.<x> = PolynomialRing(F)

# 构造格基矩阵
# 应用 LLL
# 从规约基中提取私钥
"""
```

## 格攻击通用模板

```python
# 当遇到以下场景时考虑格攻击：
# 1. 多条等式有未知数和 "小误差"
# 2. 部分私钥/部分明文恢复
# 3. 规约到格最近向量问题

# 步骤：
# 1. 将问题建模为格中的 CVP/SVP
# 2. 构造格基矩阵
# 3. 使用 LLL/BKZ 规约
# 4. 从规约基提取解
```
