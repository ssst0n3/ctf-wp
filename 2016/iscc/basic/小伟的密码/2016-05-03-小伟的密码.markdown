---
layout:     post
title:      "小伟的密码"
subtitle:   "iscc2016-Basic"
date:       2016-05-03 23:15:00
author:     "ssst0n3"
header-img: "img/post-bg-01.jpg"
---
# 小伟的密码
`score: 100` `type: crypto`

## 题目
小伟将自己神秘网站的密码保存在了附件中，并进行了他自认为保险的加密方法，请破解它吧。

## wp
打开题目提供的压缩包，发现一个压缩软件'恒波加密器'。

检索一下，发现是通过把文件夹设置为windows受保护的文件，来起到‘加密’的效果。

可以使用`attrib -s -r -h Thumbs.db`恢复

然后进入文件夹可以发现一个图片，使用winhex打开后，发现加密后的一句话

flag is ImnrelnaSicoftethgoicynyrouTo

其实是栅栏密码，有个坑是，出题人可能把这句话结尾的句号删掉了，所以导致不是很容易想到是5*6的组合

## py
```
# -*- coding: utf8 -*-
def Factor(n):
    factor = []
    for i in range(2,n):
        if not n%i:
            factor.append(i)
    return factor

def railFenceDecrypt(s):
    factor = []
    factor =  Factor(len(s))
    for f in factor:
        flag = []
        for i in range(len(s)/f):
            for j in range(f):
                flag.append(s[i+j*len(s)/f])
        print ''.join(flag)

s = "ImnrelnaSicoftethgoicynyrouTo."
railFenceDecrypt(s)
```
