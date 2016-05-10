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
