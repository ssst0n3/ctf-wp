# 心灵鸡汤
`score: 100` `type: crypto,basic`
## 题目
本程序中暗藏了一句加密的心灵鸡汤，找到它并对其进行解密
## wp
用winhex打开，发现里面藏了一句心灵鸡汤

`DEath IS JUST A PaRT oF lIFE sOMeTHInG wE'RE aLL dESTInED TO dO`

看着很像培根密码，写个脚本跑了一下

## py
```
# -*- coding: utf8 -*-
##生成bacon box
##box = {}
##for i in range(26):
##    box[i] = chr(i+65)

box = {0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'E', 5: 'F', 6: 'G', 7: 'H', 8: 'I', 9: 'J', 10: 'K', 11: 'L', 12: 'M', 13: 'N', 14: 'O', 15: 'P', 16: 'Q', 17: 'R', 18: 'S', 19: 'T', 20: 'U', 21: 'V', 22: 'W', 23: 'X', 24: 'Y', 25: 'Z'}

def baconDecrypt(s):
    p = []
    flag = []
    for i in range(len(s)):
        if s[i].isupper():
            p.append('0')
        elif s[i].islower():
            p.append('1')
    for i in range(len(p)/5):
        flag.append(box[int(''.join(p[i*5:i*5+5]), 2)])

    return ''.join(flag)

s = "DEath IS JUST A PaRT oF lIFE sOMeTHInG wE'RE aLL dESTInED TO dO"
print baconDecrypt(s)
```
