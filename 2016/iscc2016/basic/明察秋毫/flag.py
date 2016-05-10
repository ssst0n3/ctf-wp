s = "Jr1p0zr2VfPp"
p = list(s)
for i in range(26):
    for j in range(len(s)):
        if s[j].isupper():
            p[j] = chr((ord(s[j])-65+i)%26+65)
        elif s[j].islower():
            p[j] = chr((ord(s[j])-97+i)%26+97)
    print ''.join(p)
