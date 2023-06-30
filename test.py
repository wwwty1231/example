from LB_Crypto.Math import *    #实现常见算法
from LB_Crypto.SM2 import *     #数字签名算法
from LB_Crypto.SM3 import *     #哈希算法
from LB_Crypto.SM4 import *     #分组密码算法
from LB_Crypto.RSA import *     #公钥密码算法

print('---now test Math---')
assert (is_prime(13))
#  assert (is_prime(1))
#  assert (is_prime(2.33))
print('is_prime ok!')

assert (gcd(22224, 666) == 6)
#  assert (gcd(3, 4) == 1)  
print('gcd ok!')

assert (EX_Euclid(3, 4) == (1, -1, 1))
print('exgcd ok!')

assert (fast_pow(2, 3, 5) == 3)
print('fast_pow ok!')

assert(invmod(2, 11) == 6)
print('invmod ok!')

assert (is_prime(get_bigPrime(233)))
print('get_bigPrime ok!')

print('---now test SM4---')
key = "0x557cfb9c1c78b048ae02bf5c88bc781a"
IV = "0xb5e6886305720c08aed644c3dfc36cd4"
s = SM4(key)
s.CTR(key, IV, "LB_Crypto_main\LB_Crypto\SM4CTR_input.txt", 1)
s.CTR(key, IV, "LB_Crypto_main\LB_Crypto\SM4CTR_output.txt", 0)

with open("LB_Crypto_main\LB_Crypto\SM4CTR_output.txt") as f1:
    c1 = f1.read()
with open('LB_Crypto_main\LB_Crypto\SM4CTR_input.txt') as f2:
    c2 = f2.read()
    
    assert c1 == c2
f1.close()
f2.close()
print('SM4_CTR ok!')
    

print('---now test SM3---')
sm3 = SM3()
print('---now test SM3_digest---')

print(sm3.digest("助教哥哥好帅姐姐好漂亮"))
print('---now test SM3_digest for file operation ---')
print(sm3.digest("助教哥哥好帅姐姐好漂亮",1))


print('---now test SM2---')
sm2 = SM2(54492052985589574080443685629857027481671841726313362585597978545915325572248
    ,45183185393608134601425506985501881231876135519103376096391853873370470098074
    ,60275702009245096385686171515219896416297121499402250955537857683885541941187
    ,[29905514254078361236418469080477708234343499662916671209092838329800180225085, 2940593737975541915790390447892157254280677083040126061230851964063234001314]
    ,60275702009245096385686171515219896415919644698453424055561665251330296281527)
print(sm2.Sign("ALICE123@YAHOO.COM",[4927346340877997421592888003129352901369751434954921663604743238822873158794, 56090775331359075302546016414740579914612192649583459645010750108260086900823]
    ,'message digest',8387551947784012071400071471596312053542870740821494713120726177333060924003
    ,49165263701565432377505549247848435858362931747789390865593867043744446085487))

print(sm2.Verfy("neverGonnaGive@You.up",[21981408064932226135301202771561762143335985281913055880427170456330466891349,28028589283980403447494504310906074608090471180368249734410319713138692249995]
    ,"never gonna let you down",48063449755609876878532292799059389653047118380814680452731271756018810958400
    ,12071032352070378296001266231648972411992535359641329464973392771258376729799))


print('---now test RSA---')

rsa = RSA(552)
n, e = rsa.gen_publickey()
d = rsa.gen_privatekey()
message = 8267188997198709383102216295528861867050429668709122381362481797742114635297750

cipher = rsa.encrypt(message, e, n)
print("加密密文为"+str(cipher))
m = rsa.decrypt(cipher, d, n)
print("解密明文为"+str(m))
if m == message:
    print("-------RSA ok!------")
else:
    print("-------RSA fail------")