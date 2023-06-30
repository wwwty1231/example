import random
import binascii


#将字符串转为大整数
def s2n(s):
   n=s.encode('utf-8').hex()
   n=int(n,16)
   return n

#将大整数转为字符串
def n2s(n):
   stemp1=hex(n)[2:]
   if len(stemp1)%2!=0:
      stemp1='0'+stemp1
   stemp2=stemp1.encode('utf-8')

   s=binascii.unhexlify(stemp2)
   print(s)
   return s.decode('utf-8')

def gcd(a,b):return gcd(b, a % b) if b else a

def getRandomNBitInteger(N):
    return random.randint(2 ** (N - 1), 2 ** N)

def EX_Euclid(a, b):  # 扩展欧几里得算法
    if b == 0:
        return a, 1, 0
    else:
        (g, x_tmp, y_tmp) = EX_Euclid(b, a % b)
        x = y_tmp
        y = x_tmp - ((a // b) * y_tmp)
        return g, x, y
    
def bin_length(b):
    count = 0
    while b != 0:
        count = count + 1
        b = b >> 1
    return count

#快速模幂
def fast_pow(b, n, mod):
    c = 1
    len = bin_length(n)
    for i in range (len,0,-1):
        c = c * c % mod
        if (n >> (i - 1) & 1) == 1:
            c = c * b % mod
    return c
#求逆元
def invmod(e,mod):
    s = EX_Euclid(e,mod)
    if  s[0] == 1 :
        return  s[1] % mod
    
def is_prime(n, s=10):
    """米勒拉宾法判断是否为素数
    、
    Returns:
        : True for yes
    """
    for _ in range (0,s):
        # 判断n是否为偶数或2
        if n ==2 :
            return True
        a = random.randint(2,n-1)
        if n & 1 ==0 or 1 < gcd(a,n) < n:
            return False
        
        #将n-1分解为2^k*q
        q, k = n - 1, 0
        while q & 1 == 0:
            q = q >> 1
            k += 1

        #进行k轮测试
        a = fast_pow(a,q,n)
        if a == 1 or a == n - 1:
            continue
        for i in range(0,k-1):
            a = a**2 % n
            if a == n - 1 :
                break
        else:       
            return False
    return True 

def get_bigPrime(N):
    """生成N位大素数"""
    number = getRandomNBitInteger(N) | 1
    while (not is_prime(number)):
        number = number + 2
    return number