# -*- coding: utf8 -*-
def Factor(n):
    factor = []
    for i in range(2,n):
        if not n%i:
            factor.append(i)
    return factor
        
def railFenceDecrypt(s):
    factor = []
    factor =  Factor(len(s))
    for f in factor:
        flag = []
        for i in range(len(s)/f):
            for j in range(f):
                flag.append(s[i+j*len(s)/f])
        print ''.join(flag)

s = "ImnrelnaSicoftethgoicynyrouTo."
railFenceDecrypt(s)
