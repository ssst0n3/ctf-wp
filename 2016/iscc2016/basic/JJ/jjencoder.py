# -*- coding: cp936 -*-
# jjencode: http://utf-8.jp/public/jjencode.html

s = """
# 1.仅支持ascii字符
# 2.没有palindrome功能
# 3.暂时不能替换$为别的字符
# 4.换行需要自行转义处理。

# 对于某些字母,jjencode的作者使用的是8进制编码,不能很能理解为什么不用16进制
# 原作者有些可以直接获取并且预定义的字母(contructor)，不直接获取，而是采用进制编码的方式混淆，这一点我也不能理解

# 使用说明:
>>> import jjencoder
>>> print jjencode(r'alert("hello jjencode!")')
>>> print jjdecode(r'$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+"")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._=(!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\\""+$.$_$_+(![]+"")[$._$_]+$.$$$_+"\\\\"+$.__$+$.$$_+$._$_+$.__+"(\\\\\\"\\\\"+$.__$+$.$_$+$.___+$.$$$_+(![]+"")[$._$_]+(![]+"")[$._$_]+$._$+"\\\\"+$.$__+$.___+"\\\\"+$.__$+$.$_$+$._$_+"\\\\"+$.__$+$.$_$+$._$_+$.$$$_+"\\\\"+$.__$+$.$_$+$.$$_+$.$$__+$._$+$.$$_$+$.$$$_+"!\\\\\\")"+"\\"")())();')
"""

print s

import re
# 固定前缀，为了构造0-9,a-f,function
prefix = (
        "$=~[];" +                              # ~表示按位取反，按位取反首先会把运算数转换成32位数字,js中[]被转换成0,则$=~[]=-1;同样的,~{}=-1
        "$={" +                                 # $={}
                "___:++$," +                    # $.___ = 0
                '$$$$:(![]+"")[$],' +           # $.$$$$ = (![]+"")[$] = (false+"")[0] = "f" 
                "__$:++$," +                    # $.__$ = 1        
                '$_$_:(![]+"")[$],' +           # $.$_$_ = "a" 
                "_$_:++$," +                    # $._$_ = 2
                '$_$$:({}+"")[$],'+             # $.$_$$ = ({}+"")[$] = "[object Object]"[2] = "b"; 这里涉及到js引擎如何对加法运算进行操作：1.先转换两个运算数为原始值2.如果两者至少有一个字符串则为字符串连接操作3.否则转换为数字类型;类似的,[]+[]='',[]+{}='[object Object]',String({})='[object Object]' ...
                '$$_$:($[$]+"")[$],' +          # $.$$_$ = ($[$]+"")[$] = (undefined+"")[2] = "d"
                "_$$:++$," +                    # $._$$ = 3
                '$$$_:(!""+"")[$],' +           # $.$$$_ = (true+"")[3] = "e"
                "$__:++$," +                    # $.$__ = 4
                "$_$:++$," +                    # $.$_$ = 5
                '$$__:({}+"")[$],' +            # $.$$__ = "[object Object]"[5] = "c"
                "$$_:++$," +                    # $.$$_ = 6
                "$$$:++$," +                    # $.$$$ = 7
                "$___:++$," +                   # $.$___ = 8
                "$__$:++$" +                    # $.$__$ = 9
        "};" +
        '$.$_='+                                # "constructor"
                '($.$_=$+"")[$.$_$]+'+          # $.$_ = $+"" = {}+""="[object Object]"  ($.$_ = $+"")[$.$_$] ="[object Object]"[5]="c"
                '($._$=$.$_[$.__$])+'+          # $._$=$.$_[$.__$]=$._$[1]="o"   
                '($.$$=($.$+"")[$.__$])+'+      # $.$$=($.$+"")[$.__$]="undefined"[1]="n"
                '((!$)+"")[$._$$]+'+            # ((!$)+"")[$._$$]="false"[3]="s"
                '($.__=$.$_[$.$$_])+'+          # $.__=$.$_[$.$$_]=$.$_[6]="t"
                '($.$=(!""+"")[$.__$])+'+       # $.$=(!""+"")[$.__$]="true"[1]="r"
                '($._=(!""+"")[$._$_])+'+       # $._=(!""+"")[$._$_]="u"
                '$.$_[$.$_$]+'+                 # $.$_[$.$_$]="c"
                '$.__+$._$+$.$;'+               # $.__="t" $._$="o" $.$="r"
        # $.$$="return"        $.$+(!""+"")[$._$$]="r"+"true"[3]="re" $.__="t" $._="u" $.$="r" $.$$="n"
        '$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;'+
        # $.$=($.___)[$.$_][$.$_]=0["contructor"]["constructor"]=(function String() { [native code] })["constructor"]=function Function() { [native code] }
        # contructor为属性,一般通过object.contructor调用,这里很妙
        '$.$=($.___)[$.$_][$.$_];'
)
prefixBox = [ "___", "__$", "_$_", "_$$", "$__", "$_$", "$$_", "$$$", "$___", "$__$", "$_$_", "$_$$", "$$__", "$$_$", "$$$_", "$$$$"]

str_l = '(![]+"")[$._$_]+'
str_o = "$._$+"
str_t = "$.__+"
str_u = "$._+"

predefinedBox = {}
for i in range(16):
        predefinedBox["$." + prefixBox[i]+"+"]= hex(i)[2]
predefinedBox[str_l] = 'l'
predefinedBox[str_o] = 'o'
predefinedBox[str_t] = 't'
predefinedBox[str_u] = 'u'
def canBeConfused(n):
        if ((0x30 <= n and n <= 0x39) or (0x61 <= n and n <= 0x66) or n == 0x6c or n == 0x6f or n == 0x74 or n == 0x75):
                return True
        return False

def asciiToOct(n):
        h = '\\\\"+'
        for i in re.findall("[0-9]", oct(n), re.I)[1:]:
                h += "$." + prefixBox[int(i)] + "+"
        return h

def octToChar(text):
        num = "0"
        if text.find('\\\\"') == 1:
                text = text[5:]
                for i in range(3):
                        # 空格
                        if num == "040":
                                break
                        num += predefinedBox[text[:text.find("+")+1]]
                        text = text[text.find("+")+1:]
                num = chr(int(num,8))
                return text, num
        return text, ""

def asciiToHex(n):
        h = '\\\\x"+'
        for i in re.findall("[0-9a-f]", hex(n), re.I)[1:]:
                h += "$." + prefixBox[int(i, 16)] + "+"
        return h

def decodePredefinedChar(text):
        for key,value in predefinedBox.items():
                if text.find(key) == 0:
                        text = text[len(key):]
                        return text, value
        return text, ""

def decodeSymbol(text):
        value = ""
        # 第一次出现
        n = ord(text[1])
        if text.find('"') == 0 and ((0x21 <= n and n <= 0x2f) or (0x3A <= n and n <= 0x40) or (0x5b <=n and n <= 0x60) or (0x7b <=n and n <= 0x7f)):
                if n != 0x5c:
                        value += text[1]
                        text = text[2:]
                else:
                        text = text[1:]
                # 循环验证
                while(text.find('"+') != 0):
                        n = ord(text[0])
                        if n != 0x5c:
                                value += text[0]
                                text = text[1:]
                        else:
                                if text.find("\\\\\\") == 0:
                                        value += text[3]                        
                                        text = text[4:]
                                elif text.find('\\\\"') == 0:
                                        text = '"' + text
                                        text, tmpValue = octToChar(text)
                                        value += tmpValue
                                        return text, value
                                else:
                                        value += text[1]
                                        text = text[2:]
                # 最后一次出现
                text = text[2:]
                return text, value
        return text, ""
def jjencode(text):
        # 主体
        mainText = ""
        tmp = ""
        for i in range(len(text)):
                n = ord(text[i])
                # 可以被混淆的字符
                if canBeConfused(n):
                        if tmp:
                                mainText += '"' + tmp + '"+'
                                tmp = ""
                        # 0-9,a-f, 这些字符，已经在前缀中获得，这里可以直接引用
                        if ((0x30 <= n and n <= 0x39) or (0x61 <= n and n <= 0x66)):
                                # 0-9
                                if n < 0x40:
                                        index = n - 0x30
                                # a-f
                                else:
                                        index = n - 0x61 + 0x0a
                                mainText += "$." + prefixBox[index] + "+"
                        # 一些可以获得的字符
                        elif n == 0x6c:
                                mainText += str_l
                        elif n == 0x6f:
                                mainText += str_o
                        elif n == 0x74:
                                mainText += str_t
                        elif n == 0x75:
                                mainText += str_u
                # 不可以被混淆
                else:
                        # 除了控制字符、通信专用字符，空格，0-9，大小写字母的符号，这些符号无法混淆,直接输出即可
                        if ((0x21 <= n and n <= 0x2f) or (0x3A <= n and n <= 0x40) or (0x5b <=n and n <= 0x60) or (0x7b <=n and n <= 0x7f)):
                                # ",\ 这两个字符比较特殊,需要转义
                                if (n == 0x22 or n == 0x5c):
                                        tmp += "\\\\\\"
                                tmp += text[i]
                        # 控制字符、通信专用字符，空格，大写字母, ghijkmnpqrsvwxyz
                        elif n < 128:
                                if tmp:
                                        mainText += '"' + tmp
                                        tmp = ""
                                else:
                                        mainText += '"'
                                mainText += asciiToOct(n)

        if tmp:
                mainText += '"' + tmp + '"+'
                
        # 后缀，为了调用匿名函数
        # $.$ = function Function() { [native code] }
        # $.$$+"\""alert("s")"\"" = 'return "\""+mainText+"\""' = 'return"mainText"'
        # $.$('return"mainText"')() = function anonymous(){return"mainText"}()=(自解码)"text"
        # $.$($.$('return"mainText"')())() = $.$("text")() = function anonymous(){text}()=text(执行)
        encodedText = prefix + '$.$($.$($.$$+"\\""+' + mainText + '"\\"")())();'
        return encodedText

def jjdecode(text):
        # decodedText = 'alert("al1\\"\\\\%")'
        # text = """$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+"")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._=(!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\""+$.$_$_+(![]+"")[$._$_]+$.$$$_+"\\"+$.__$+$.$$_+$._$_+$.__+"(\\\""+$.$_$_+(![]+"")[$._$_]+$.__$+"\\\\\\\"\\\\\\\\%\\\")"+"\"")())();"""
        text = text.replace(" ","")
        # 去除前缀后缀，提取主体
        try:
                startPos = text.index('$.$($.$($.$$+"\\""+')+18
                endPos = text.index('"\\"")())();')
        except:
                print "不是标准jjencode格式,确定这串代码可以直接运行？"
                
        if startPos < endPos:
                text = text[startPos:endPos]
        else:
                raise "数据主体缺失"
        
        # 每个字符串采用相加的方式结合
        # 因此只需要判断+所在位置，即可判断字符(但首先需要把lotu这几个特殊字符筛选掉)
        decodedText = ""
        while(text != ""):
                # 0-9a-f,l,u,t,o
                text, value1 = decodePredefinedChar(text)
                # 使用8进制混淆的字母、空格、特殊符号
                text, value2 = octToChar(text)
                # 符号
                text, value3 = decodeSymbol(text)
                decodedText += value1 +value2 + value3
        return decodedText
