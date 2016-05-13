# 明察秋毫
`score: 50` `type: crypto,basic`
## 题目
都说flag在这里…我怎么看不到？？？[点击这里](http://iscc.isclab.org.cn/basic)

## wp
查看源代码，找到
maybe not flag : Jr1p0zr2VfPp

移位密码，注意判断字母大小写，并且数字无变化

## code
```
s = "Jr1p0zr2VfPp"
p = list(s)
for i in range(26):
    for j in range(len(s)):
        if s[j].isupper():
            p[j] = chr((ord(s[j])-65+i)%26+65)
        elif s[j].islower():
            p[j] = chr((ord(s[j])-97+i)%26+97)
    print ''.join(p)

```
