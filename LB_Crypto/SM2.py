import hashlib
import math
from LB_Crypto.SM3 import SM3


class SM2:
    #a,b,p,G,n = 0,0,0,[0,0],0
    # y^2 = x^3 + ax + b (mod p)
    def __init__(self, a, b ,p, G, n):
        self.a = a
        self.b = b
        self.p = p
        self.G = G
        self.n = n
        if not isinstance(p, int):
            raise Exception("请检查输入p的类型是否正确")
        if not isinstance(a, int):
            raise Exception("请检查输入a的类型是否正确")

    


    
    def Sign(self, ID, P, M, d, K):
        
        ID = ID.encode('utf-8').hex()
        ENTL = hex(len(ID) * 4)[2:]
        while len(ENTL) < 4:
            ENTL = '0' + ENTL
        tmp = ENTL + ID + int2byte(self.a, self.p) + int2byte(self.b, self.p) + int2byte(self.G[0], self.p) + int2byte(self.G[1], self.p) + int2byte(P[0], self.p) + int2byte(P[1], self.p)
        Za = SM3.digest(tmp,0,1)
        #print(Za)
        
        M_er = Za + M.encode('utf-8').hex()
        e = int(SM3.digest(M_er,0,1), 16)
        B = ECC_mul(K, self.G[0], self.G[1], self.a, self.p)

        r = (e + B[0]) % self.n
        s = (invmod(1 + d, self.n) * (K - r * d)) % self.n
        return r,s

    
    def Verfy(self, ID, P, M, r, s):
        ID = ID.encode('utf-8').hex()
        E = hex(len(ID) * 4)[2:]
        while len(E) < 4:
            E = '0' + E
        tmp = E + ID + int2byte(self.a, self.p) + int2byte(self.b, self.p) + int2byte(self.G[0], self.p) + int2byte(self.G[1], self.p) + int2byte(P[0],self.p) + int2byte(P[1], self.p)
        Za = SM3.digest(tmp,0,1)
        
        M = Za + M.encode('utf-8').hex()
        e = int(SM3.digest(M,0,1), 16)
        t = (r + s) % self.n
        buf = ECC_add(ECC_mul(s, self.G[0], self.G[1], self.a, self.p), ECC_mul(t, P[0], P[1], self.a, self.p), self.a, self.p)
        R = (e + buf[0]) % self.n
        if R == r:
            return 'SM2签名结果：True'
        else:
            return 'SM2签名结果：False'
        
def Ex_Euclid(a, b):  # 扩展欧几里得算法
    if b == 0:
        return a, 1, 0
    else:
        (g, x_tmp, y_tmp) = Ex_Euclid(b, a % b)
        x = y_tmp
        y = x_tmp - ((a // b) * y_tmp)
        return g, x, y

def invmod(e,mod):
    s = Ex_Euclid(e,mod)
    if  s[0] == 1 :
        return  s[1] % mod

def ECC_add(A, B, a, p):
    x1, y1 = A[0], A[1]
    x2, y2 = B[0], B[1]
    if x1 == x2 and y1 == y2:
        ECC_lambda = ((3*(x1**2) + a) * invmod(2 * y1, p)) % p
    else:
        #无穷远点+点P = 点P
        if x1 == 0 and y1 == 0:
            result = (x2, y2)
            return result
        if x2 == 0 and y2 == 0:
            result = (x1, y1)
            return result
        if x1 == x2 and (y1 + y2) % p == 0:
            result = (0, 0)
            return result
        ECC_lambda = ((y2 - y1) * invmod(x2 - x1, p)) % p
    x3 = (ECC_lambda**2-x1-x2) % p
    y3 = (ECC_lambda*(x1-x3)-y1) % p
    result = (x3, y3)
    return result

def ECC_mul(num, x1, y1, a, p):    
    #椭圆曲线内的倍点（乘法）计算 （类比快速模幂)

    num_binary = bin(num)[2:][::-1]
    result = (0, 0)
    array = (x1, y1)
    for item in num_binary:
        if item == '1':
            result = ECC_add(array, result, a, p)
            array = ECC_add(array, array, a, p)
        else:
            array = ECC_add(array, array, a, p)
    return result

def int2byte( a, p):
    t = math.ceil(math.log(p, 2))
    a = hex(a)[2:]
    while len(a) < math.ceil(t / 8) * 2:
        a = '0' + a
    return a