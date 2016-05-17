# -*- coding: cp936 -*-
# jjencode����ѡ��global variable,Ĭ��Ϊ`$`�������˽�`$`�滻����`''`���ѡ�������ǰ����п��ܳ���ȫ�ֱ����ĵط����ϾͿ�����
# ����ȫ�ֱ����ĵط�������
# 1. 0-9,a-f,'l','o','t','u'��Щ�ַ����洢��ȫ�ֱ���(�ֵ�)�У���Ҫͨ��ȫ�ֱ������á�
# 2. ǰ׺�еĳ�ʼ������
# 3. ʹ�ð˽��ƻ������ַ�����Ҫͨ��ȫ�ֱ����������֣���1����ʽ��ͬ
# 

import jjencoder
import re

# �̶�ǰ׺
prefix = r'$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+"")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._=(!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];'
s = r"""=~[];={___:++,$$$$:(![]+"")[],__$:++,$_$_:(![]+"")[],_$_:++,$_$$:({}+"")[],$$_$:([]+"")[],_$$:++,$$$_:(!""+"")[],$__:++,$_$:++,$$__:({}+"")[],$$_:++,$$$:++,$___:++,$__$:++};.$_=(.$_=+"")[.$_$]+(._$=.$_[.__$])+(.$$=(.$+"")[.__$])+((!)+"")[._$$]+(.__=.$_[.$$_])+(.$=(!""+"")[.__$])+(._=(!""+"")[._$_])+.$_[.$_$]+.__+._$+.$;.$$=.$+(!""+"")[._$$]+.__+._+.$+.$$;.$=(.___)[.$_][.$_];.$(.$(.$$+"\""+.$$$_+"\\"+.__$+.$$_+.$$_+.$_$_+(![]+"")[._$_]+"("+.$$$$+._+"\\"+.__$+.$_$+.$$_+.$$__+.__+"\\"+.__$+.$_$+.__$+._$+"\\"+.__$+.$_$+.$$_+"(\\"+.__$+.$$_+.___+","+.$_$_+","+.$$__+",\\"+.__$+.$_$+._$$+","+.$$$_+","+.$$_$+"){"+.$$$_+"="+.$$$$+._+"\\"+.__$+.$_$+.$$_+.$$__+.__+"\\"+.__$+.$_$+.__$+._$+"\\"+.__$+.$_$+.$$_+"("+.$$__+"){\\"+.__$+.$$_+._$_+.$$$_+.__+._+"\\"+.__$+.$$_+._$_+"\\"+.__$+.$_$+.$$_+"("+.$$__+"<"+.$_$_+"?'':"+.$$$_+"(\\"+.__$+.$$_+.___+.$_$_+"\\"+.__$+.$$_+._$_+"\\"+.__$+.$$_+._$$+.$$$_+"\\"+.__$+.__$+.__$+"\\"+.__$+.$_$+.$$_+.__+"("+.$$__+"/"+.$_$_+")))+(("+.$$__+"="+.$$__+"%"+.$_$_+")>"+._$$+.$_$+"?\\"+.__$+._$_+._$$+.__+"\\"+.__$+.$$_+._$_+"\\"+.__$+.$_$+.__$+"\\"+.__$+.$_$+.$$_+"\\"+.__$+.$__+.$$$+"."+.$$$$+"\\"+.__$+.$$_+._$_+._$+"\\"+.__$+.$_$+.$_$+"\\"+.__$+.___+._$$+"\\"+.__$+.$_$+.___+.$_$_+"\\"+.__$+.$$_+._$_+"\\"+.__$+.___+._$$+._$+.$$_$+.$$$_+"("+.$$__+"+"+._$_+.$__$+"):"+.$$__+"."+.__+._$+"\\"+.__$+._$_+._$$+.__+"\\"+.__$+.$$_+._$_+"\\"+.__$+.$_$+.__$+"\\"+.__$+.$_$+.$$_+"\\"+.__$+.$__+.$$$+"("+._$$+.$$_+"))};\\"+.__$+.$_$+.__$+.$$$$+"(!''.\\"+.__$+.$$_+._$_+.$$$_+"\\"+.__$+.$$_+.___+(![]+"")[._$_]+.$_$_+.$$__+.$$$_+"(/^/,\\"+.__$+._$_+._$$+.__+"\\"+.__$+.$$_+._$_+"\\"+.__$+.$_$+.__$+"\\"+.__$+.$_$+.$$_+"\\"+.__$+.$__+.$$$+")){\\"+.__$+.$$_+.$$$+"\\"+.__$+.$_$+.___+"\\"+.__$+.$_$+.__$+(![]+"")[._$_]+.$$$_+"("+.$$__+"--)"+.$$_$+"["+.$$$_+"("+.$$__+")]=\\"+.__$+.$_$+._$$+"["+.$$__+"]||"+.$$$_+"("+.$$__+");\\"+.__$+.$_$+._$$+"=["+.$$$$+._+"\\"+.__$+.$_$+.$$_+.$$__+.__+"\\"+.__$+.$_$+.__$+._$+"\\"+.__$+.$_$+.$$_+"("+.$$$_+"){\\"+.__$+.$$_+._$_+.$$$_+.__+._+"\\"+.__$+.$$_+._$_+"\\"+.__$+.$_$+.$$_+"\\"+.$__+.___+.$$_$+"["+.$$$_+"]}];"+.$$$_+"="+.$$$$+._+"\\"+.__$+.$_$+.$$_+.$$__+.__+"\\"+.__$+.$_$+.__$+._$+"\\"+.__$+.$_$+.$$_+"(){\\"+.__$+.$$_+._$_+.$$$_+.__+._+"\\"+.__$+.$$_+._$_+"\\"+.__$+.$_$+.$$_+"'\\\\\\\\\\"+.__$+.$$_+.$$$+"+'};"+.$$__+"="+.__$+"};\\"+.__$+.$$_+.$$$+"\\"+.__$+.$_$+.___+"\\"+.__$+.$_$+.__$+(![]+"")[._$_]+.$$$_+"("+.$$__+"--)\\"+.__$+.$_$+.__$+.$$$$+"(\\"+.__$+.$_$+._$$+"["+.$$__+"])\\"+.__$+.$$_+.___+"=\\"+.__$+.$$_+.___+".\\"+.__$+.$$_+._$_+.$$$_+"\\"+.__$+.$$_+.___+(![]+"")[._$_]+.$_$_+.$$__+.$$$_+"(\\"+.__$+.$_$+.$$_+.$$$_+"\\"+.__$+.$$_+.$$$+"\\"+.$__+.___+"\\"+.__$+._$_+._$_+.$$$_+"\\"+.__$+.$__+.$$$+"\\"+.__$+.___+.$_$+"\\"+.__$+.$$$+.___+"\\"+.__$+.$$_+.___+"('\\\\\\\\"+.$_$$+"'+"+.$$$_+"("+.$$__+")+'\\\\\\\\"+.$_$$+"','\\"+.__$+.$__+.$$$+"'),\\"+.__$+.$_$+._$$+"["+.$$__+"]);\\"+.__$+.$$_+._$_+.$$$_+.__+._+"\\"+.__$+.$$_+._$_+"\\"+.__$+.$_$+.$$_+"\\"+.$__+.___+"\\"+.__$+.$$_+.___+"}('<"+.$___+">"+.$__+"(/"+.$$_+"/);<!--"+.__$+"."+.___+"."+.___+"."+._$_+"/"+.$$$+"/--><!--"+.$_$+"{"+._$$+"}--></"+.$___+">',"+.$$_+._$_+","+.$__$+",'|"+.__$+.___+"||"+._$$+.$__+.$_$$+.$$$_+.$_$+.$_$$+.$$__+.$_$$+.$$_+.$$__+.$$_+.$$$$+.___+.$_$$+.$$__+.$$$$+.$$__+.$$_+._$_+.$___+.$$_$+.$__$+.$$$_+._$$+.$__$+.___+.$$_$+.__$+._$$+.$_$$+.$_$_+.$$_+"|"+.$_$_+(![]+"")[._$_]+.$$$_+"\\"+.__$+.$$_+._$_+.__+"|"+.$$$$+(![]+"")[._$_]+.$_$_+"\\"+.__$+.$__+.$$$+.__$+._$_+"|\\"+.__$+.$_$+.___+.$_$_+"\\"+.__$+.$_$+.___+.$_$_+"|\\"+.__$+.$_$+.__$+"\\"+.__$+.$_$+.$$_+.$$__+(![]+"")[._$_]+._+.$$_$+.$$$_+.$$$$+"\\"+.__$+.$_$+.__$+(![]+"")[._$_]+.$$$_+"|\\"+.__$+.$$_+._$$+.$$__+"\\"+.__$+.$$_+._$_+"\\"+.__$+.$_$+.__$+"\\"+.__$+.$$_+.___+.__+"'.\\"+.__$+.$$_+._$$+"\\"+.__$+.$$_+.___+(![]+"")[._$_]+"\\"+.__$+.$_$+.__$+.__+"('|'),"+.___+",{}))"+"\"")())();"""

# $��һ���ֵ䣬.***֮ǰ��Ȼ��Ҫһ��$����������Ҫע��"."��Ϊ�ַ����ֵ����
# print re.findall("\.[^(\$|_)]", s)
s = re.sub('\.(?=\$|_)', '$.', s)
# �ҵ����岿��,�滻ǰ׺
s = s[s.find('$.$($.$($.$$'):]
s = prefix + s

print s
print jjencoder.jjdecode(s)