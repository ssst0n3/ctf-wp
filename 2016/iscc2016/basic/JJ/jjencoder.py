# -*- coding: cp936 -*-
# jjencode: http://utf-8.jp/public/jjencode.html

s = """
# 1.��֧��ascii�ַ�
# 2.û��palindrome����
# 3.��ʱ�����滻$Ϊ����ַ�
# 4.������Ҫ����ת�崦��

# ����ĳЩ��ĸ,jjencode������ʹ�õ���8���Ʊ���,���ܺ������Ϊʲô����16����
# ԭ������Щ����ֱ�ӻ�ȡ����Ԥ�������ĸ(contructor)����ֱ�ӻ�ȡ�����ǲ��ý��Ʊ���ķ�ʽ��������һ����Ҳ�������

# ʹ��˵��:
>>> import jjencoder
>>> print jjencode(r'alert("hello jjencode!")')
>>> print jjdecode(r'$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+"")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._=(!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\\""+$.$_$_+(![]+"")[$._$_]+$.$$$_+"\\\\"+$.__$+$.$$_+$._$_+$.__+"(\\\\\\"\\\\"+$.__$+$.$_$+$.___+$.$$$_+(![]+"")[$._$_]+(![]+"")[$._$_]+$._$+"\\\\"+$.$__+$.___+"\\\\"+$.__$+$.$_$+$._$_+"\\\\"+$.__$+$.$_$+$._$_+$.$$$_+"\\\\"+$.__$+$.$_$+$.$$_+$.$$__+$._$+$.$$_$+$.$$$_+"!\\\\\\")"+"\\"")())();')
"""

print s

import re
# �̶�ǰ׺��Ϊ�˹���0-9,a-f,function
prefix = (
        "$=~[];" +                              # ~��ʾ��λȡ������λȡ�����Ȼ��������ת����32λ����,js��[]��ת����0,��$=~[]=-1;ͬ����,~{}=-1
        "$={" +                                 # $={}
                "___:++$," +                    # $.___ = 0
                '$$$$:(![]+"")[$],' +           # $.$$$$ = (![]+"")[$] = (false+"")[0] = "f" 
                "__$:++$," +                    # $.__$ = 1        
                '$_$_:(![]+"")[$],' +           # $.$_$_ = "a" 
                "_$_:++$," +                    # $._$_ = 2
                '$_$$:({}+"")[$],'+             # $.$_$$ = ({}+"")[$] = "[object Object]"[2] = "b"; �����漰��js������ζԼӷ�������в�����1.��ת������������Ϊԭʼֵ2.�������������һ���ַ�����Ϊ�ַ������Ӳ���3.����ת��Ϊ��������;���Ƶ�,[]+[]='',[]+{}='[object Object]',String({})='[object Object]' ...
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
        # contructorΪ����,һ��ͨ��object.contructor����,�������
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
                        # �ո�
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
        # ��һ�γ���
        n = ord(text[1])
        if text.find('"') == 0 and ((0x21 <= n and n <= 0x2f) or (0x3A <= n and n <= 0x40) or (0x5b <=n and n <= 0x60) or (0x7b <=n and n <= 0x7f)):
                if n != 0x5c:
                        value += text[1]
                        text = text[2:]
                else:
                        text = text[1:]
                # ѭ����֤
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
                # ���һ�γ���
                text = text[2:]
                return text, value
        return text, ""
def jjencode(text):
        # ����
        mainText = ""
        tmp = ""
        for i in range(len(text)):
                n = ord(text[i])
                # ���Ա��������ַ�
                if canBeConfused(n):
                        if tmp:
                                mainText += '"' + tmp + '"+'
                                tmp = ""
                        # 0-9,a-f, ��Щ�ַ����Ѿ���ǰ׺�л�ã��������ֱ������
                        if ((0x30 <= n and n <= 0x39) or (0x61 <= n and n <= 0x66)):
                                # 0-9
                                if n < 0x40:
                                        index = n - 0x30
                                # a-f
                                else:
                                        index = n - 0x61 + 0x0a
                                mainText += "$." + prefixBox[index] + "+"
                        # һЩ���Ի�õ��ַ�
                        elif n == 0x6c:
                                mainText += str_l
                        elif n == 0x6f:
                                mainText += str_o
                        elif n == 0x74:
                                mainText += str_t
                        elif n == 0x75:
                                mainText += str_u
                # �����Ա�����
                else:
                        # ���˿����ַ���ͨ��ר���ַ����ո�0-9����Сд��ĸ�ķ��ţ���Щ�����޷�����,ֱ���������
                        if ((0x21 <= n and n <= 0x2f) or (0x3A <= n and n <= 0x40) or (0x5b <=n and n <= 0x60) or (0x7b <=n and n <= 0x7f)):
                                # ",\ �������ַ��Ƚ�����,��Ҫת��
                                if (n == 0x22 or n == 0x5c):
                                        tmp += "\\\\\\"
                                tmp += text[i]
                        # �����ַ���ͨ��ר���ַ����ո񣬴�д��ĸ, ghijkmnpqrsvwxyz
                        elif n < 128:
                                if tmp:
                                        mainText += '"' + tmp
                                        tmp = ""
                                else:
                                        mainText += '"'
                                mainText += asciiToOct(n)

        if tmp:
                mainText += '"' + tmp + '"+'
                
        # ��׺��Ϊ�˵�����������
        # $.$ = function Function() { [native code] }
        # $.$$+"\""alert("s")"\"" = 'return "\""+mainText+"\""' = 'return"mainText"'
        # $.$('return"mainText"')() = function anonymous(){return"mainText"}()=(�Խ���)"text"
        # $.$($.$('return"mainText"')())() = $.$("text")() = function anonymous(){text}()=text(ִ��)
        encodedText = prefix + '$.$($.$($.$$+"\\""+' + mainText + '"\\"")())();'
        return encodedText

def jjdecode(text):
        # decodedText = 'alert("al1\\"\\\\%")'
        # text = """$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+"")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._=(!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\""+$.$_$_+(![]+"")[$._$_]+$.$$$_+"\\"+$.__$+$.$$_+$._$_+$.__+"(\\\""+$.$_$_+(![]+"")[$._$_]+$.__$+"\\\\\\\"\\\\\\\\%\\\")"+"\"")())();"""
        text = text.replace(" ","")
        # ȥ��ǰ׺��׺����ȡ����
        try:
                startPos = text.index('$.$($.$($.$$+"\\""+')+18
                endPos = text.index('"\\"")())();')
        except:
                print "���Ǳ�׼jjencode��ʽ,ȷ���⴮�������ֱ�����У�"
                
        if startPos < endPos:
                text = text[startPos:endPos]
        else:
                raise "��������ȱʧ"
        
        # ÿ���ַ���������ӵķ�ʽ���
        # ���ֻ��Ҫ�ж�+����λ�ã������ж��ַ�(��������Ҫ��lotu�⼸�������ַ�ɸѡ��)
        decodedText = ""
        while(text != ""):
                # 0-9a-f,l,u,t,o
                text, value1 = decodePredefinedChar(text)
                # ʹ��8���ƻ�������ĸ���ո��������
                text, value2 = octToChar(text)
                # ����
                text, value3 = decodeSymbol(text)
                decodedText += value1 +value2 + value3
        return decodedText
