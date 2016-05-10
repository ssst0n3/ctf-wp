# Find to me  
`Score: 50` `Type:Basic,crypto`

已知仿射加密变换为c=（11m+8）mod26，试对密文sjoyuxzr解密

## Writeup
### 仿射密码
`C= Ek(m)=(k1m+k2) mod n`

`M= Dk(c)=k3(c- k2) mod n（其中（k3 ×k1）mod26 = 1）`

于是根据加密解密规则写出脚本，注意'a'=0

```
# -*- coding: cp936 -*-
# 已知仿射加密变换为c=（11m+8）mod26，试对密文sjoyuxzr解密
def exgcd(a,b):
    # x == s * a + t * b
    # y == u * a + v * b
    x, y = a, b
    s, t, u, v = 1, 0, 0, 1
    while y:
        x, y, z = y, x % y, x // y
        s, t, u, v = u, v, s - u * z, t - v * z
    return s%26

def decrypt_affine(a, b, c):
    re_a = exgcd(a, 26)
    p = []
    for i in range (len(c)):
        p.append(chr((ord(c[i])-97-b)*re_a%26+97))
    return ''.join(p)

print decrypt_affine(11, 8, "sjoyuxzr")
```
