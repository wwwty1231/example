import hashlib
from LB_Crypto.Math import *
import random

def CRT(c,p,q,d):  
    d1 = d % (p-1)
    d2 = d % (q-1)
    c1 = c % p
    c2 = c % q
    m1 = fast_pow(c1,d1,p)
    m2 = fast_pow(c2,d2,q)
    Q1 = invmod(q,p)
    h = (Q1*(m1-m2))%p
    M = m2+h*q
    return M

class RSA:
    
    def __init__(self, nbit) -> None:
        p = get_bigPrime(nbit)         #p,q位数相差不大保证p,q相差不大也不小,不会被轻易分解
        q = get_bigPrime(nbit//2 * 2 + 3)
        # if Math.gcd(p-1,q-1) > 2:
        #     return RSA.gen_key(self,nbit)
        phi = (p-1)*(q-1)
        self.p, self.q = p, q
        n = p * q
        e = random.randint(n//100,n) | 1           #e足够大可以防止“低加密指数攻击”
        while(EX_Euclid(e,phi)[0] != 1):
            e = e + 2
        self.e = e
        
    
    def gen_privatekey(self):
        p, q = self.p, self.q
        e = self.e
        phi = (p-1)*(q-1)
        d = invmod(e,phi)
        print("gen_privatekey ok!")
        return d
    
    
    def gen_publickey(self):
        p, q = self.p, self.q
        e = self.e
        n = p * q
        print("gen_publickey ok!")
        return n, e
    
    def encrypt(self, message, e,  n):
        if not isinstance(n, int):
            raise Exception("请检查输入的n是否为正整数")
        c = fast_pow(message, e, n)
        return c

    def decrypt(self, cipher, d, n):
        if not isinstance(n, int):
            raise Exception("请检查输入的n是否为正整数")
        c =fast_pow(cipher, d, n)
        return c


