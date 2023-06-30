class SM4:

    MK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
    Sbox = [[214, 144, 233, 254, 204, 225, 61, 183, 22, 182, 20, 194, 40, 251, 44, 5],
            [43, 103, 154, 118, 42, 190, 4, 195, 170, 68, 19, 38, 73, 134, 6, 153],
            [156, 66, 80, 244, 145, 239, 152, 122, 51, 84, 11, 67, 237, 207, 172, 98],
            [228, 179, 28, 169, 201, 8, 232, 149, 128, 223, 148, 250, 117, 143, 63, 166],
            [71, 7, 167, 252, 243, 115, 23, 186, 131, 89, 60, 25, 230, 133, 79, 168],
            [104, 107, 129, 178, 113, 100, 218, 139, 248, 235, 15, 75, 112, 86, 157, 53],
            [30, 36, 14, 94, 99, 88, 209, 162, 37, 34, 124, 59, 1, 33, 120, 135],
            [212, 0, 70, 87, 159, 211, 39, 82, 76, 54, 2, 231, 160, 196, 200, 158],
            [234, 191, 138, 210, 64, 199, 56, 181, 163, 247, 242, 206, 249, 97, 21, 161],
            [224, 174, 93, 164, 155, 52, 26, 85, 173, 147, 50, 48, 245, 140, 177, 227],
            [29, 246, 226, 46, 130, 102, 202, 96, 192, 41, 35, 171, 13, 83, 78, 111],
            [213, 219, 55, 69, 222, 253, 142, 47, 3, 255, 106, 114, 109, 108, 91, 81],
            [141, 27, 175, 146, 187, 221, 188, 127, 17, 217, 92, 65, 31, 16, 90, 216],
            [10, 193, 49, 136, 165, 205, 123, 189, 45, 116, 208, 18, 184, 229, 180, 176],
            [137, 105, 151, 74, 12, 150, 119, 126, 101, 185, 241, 9, 197, 110, 198, 132],
            [24, 240, 125, 236, 58, 220, 77, 32, 121, 238, 95, 62, 215, 203, 57, 72]]
    ck = [462357, 472066609, 943670861, 1415275113, 1886879365, 2358483617, 2830087869, 3301692121, 3773296373, 4228057617,
        404694573, 876298825, 1347903077, 1819507329, 2291111581, 2762715833, 3234320085, 3705924337, 4177462797,
        337322537, 808926789, 1280531041, 1752135293, 2223739545, 2695343797, 3166948049, 3638552301, 4110090761,
        269950501, 741554753, 1213159005, 1684763257]

    def __init__(self,key) -> None:    
        if not isinstance(key, str):
            raise ValueError("输入不是字符串")
        if len(key) != 34:
            raise ValueError("长度不为34")
        if key[:2]!='0x':
            raise ValueError("请检查输入的key是否符合要求")
        
        
    @classmethod
    def div(cls, n):
        # 把128bit分成4个32bit
        return [n >> 96, (n >> 64) & 0xffffffff, (n >> 32) & 0xffffffff, n & 0xffffffff]

    @classmethod
    def R(cls, state):
        #反序变换R
        res = 0
        for i in range(4):
            res <<= 32
            res |= state[i]
        return res

    @classmethod
    def SboxReplace(cls, a: int):
            #sbox变换 a 8bit
        return SM4.Sbox[a >> 4][a & 0xf]

    @classmethod
    def pbox(cls, n:int):
        # n 32bit 分成 4 个 8 bit
        a = [n >> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
        #进行sbox变换
        b = list(map(SM4.SboxReplace, a))
        return (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]

    @classmethod
    def shift(cls, num, pos):
            #32位num 循环左移 pos位
        return ((num << pos) | (num >> (32 - pos))) & 0xffffffff

    @classmethod
    def L(cls, n, type):
        if type == 1:
            #用于轮密钥生成           
            return n ^ SM4.shift(n, 13) ^ SM4.shift(n, 23)
        else:
            # 用于轮函数32轮迭代
            return n ^ SM4.shift(n, 2) ^ SM4.shift(n, 10) ^ SM4.shift(n, 18) ^ SM4.shift(n, 24)

    @classmethod
    def F(cls, a, b, c, d, e, i):
            #轮函数
        return a ^ SM4.L(SM4.pbox(b ^ c ^ d ^ e), i)

    @classmethod
    def keygen(cls, key):
        # 将初始密钥 K0,K1,K2,K3分别异或固定参数 MK0,MK1,MK2,MK3得到用于循环的密钥 k0,k1,k2,k3
        KeyWord = [(a ^ b) for a, b in zip(SM4.div(key), SM4.MK)]
        #生成轮密钥
        for i in range(32):
            KeyWord.append(SM4.F(KeyWord[i], KeyWord[i + 1], KeyWord[i + 2], KeyWord[i + 3], SM4.ck[i], 1))
        return KeyWord
    
    @classmethod
    def SM4crypt(cls, message:int, key:int, type):
        #生成轮密钥
        rk = SM4.keygen(key) if type == 1 else SM4.keygen(key)[::-1]
        #将message分成4个字
        MesWord = SM4.div(message)
        for i in range(32):
            RK = rk[i + 4] if type == 1 else rk[i]
            MesWord.append(SM4.F(MesWord[i], MesWord[i + 1], MesWord[i + 2], MesWord[i + 3], RK, 0))
        return SM4.R(MesWord[35:31:-1])

    @classmethod
    def bytes(cls, messages:str):
        results = []
        result =  messages
        result = result.replace("0x","")
        result = "0x" + result.replace(" ","")

        s = '0x'
        for i in range(2, len(result),2):
            s += result[i:i+2]
            if len(s) == 34 or i == len(result) - 2:
                results.append(s)
                s = '0x'
        return results 

    @classmethod
    def xor(cls, messgae:str, us:str):
        length = len(messgae)
        a = int(messgae,16)
        b = int(us,16)
        return '0x'+hex(a^b)[2:].zfill(length-2)

    @classmethod
    def fill_in_PKCS7(cls, message:str):
        if (len(message)-2) % 32 == 0 :
            return message + "10101010101010101010101010101010"
        else:
            return message + ("0"+hex(16 - ((len(message) -2)//2)%16)[2:]) *(16 - ((len(message) -2)//2)%16)
        
    @classmethod
    def output(cls, messgae:str):
        messgae =(messgae)[2:]
        for j in range(0, (len(messgae)), 2):    
            print("0x"+messgae[j:j+2].rjust(2,"0"),end=" ")
            
    @classmethod
    def CTR(cls, key:str, IV:str, file_path, Mode):
        """
        Args:
            file_path (str): 消息文件
            Mode (int): 1 for encrypt 0 for decrypt
        """
        if len(IV) != 34:
            raise Exception("请检查输入的IV是否为32位16进制字符串")
        if IV[:2] != '0x':
            raise Exception("请检查输入的IV是否符合要求")
        IV = int(IV,  16)
        key = int(key, 16)
        with open(file_path) as f:
            message = f.read()
            message = "0x" + message.replace("0x", "")
        f.close()
        
        messages = SM4.bytes(message)
        n = len(messages)
        for i in range(n):
            useless ="0x" + hex(SM4.SM4crypt(IV + i, key, 1))[2:].rjust(32,"0")
            if i == n-1:
                useless = useless[:len((messages[i]))]
            messages[i] =SM4.xor(messages[i], useless)
        
        with open('LB_Crypto_main\LB_Crypto\SM4CTR_output.txt', 'w') as fw:
            fw.writelines(messages)
        fw.close()
        # #输出
        # for i in range(n):
            
        #     SM4.output(messages[i])
        #     print()
        
    @classmethod
    def ECB(cls, key:str, file_path, Mode):
        """
        Args:
            file_path (str): 消息文件
            Mode (int): 1 for encrypt 0 for decrypt
        """
        with open(file_path,"r") as f:
            message = f.read()
            message = "0x" + message.replace("0x", "")
        key = int(key, 16)
        f.close()
        #messages =bytes(messages,Mode)
        if Mode == 1:
            message = SM4.fill_in_PKCS7(message)
        messages = []
        s = '0x'
        for i in range(2, len(message), 2):
            s += message[i:i+2]
            if len(s) ==34 or i == len(message) - 2:
                messages.append(int(s,16))
                s = '0x'
        n = len(messages) 
        flag = 0 #解密时最后一轮需要去填充
        for i in range(n):
            messages[i] = int( hex(SM4.SM4crypt(messages[i], key, Mode))[2:].rjust(32,"0"), 16)
            if i == n - 1:
                flag = 1
            #output(messages[i], Mode, flag) 
            messages[i] = hex(messages[i])[2:].rjust(32,"0")
            num = 0
            for j in range(0, (len(messages[i])), 2):
                if Mode == 0 and flag == 1:
                    if num == 16 - int(messages[i][30:], 16) :
                        break
                    num += 1   
                with open("LB_Crypto_main\LB_Crypto\SM4ECB_output.txt", "a") as fw:
                    fw.write("0x"+ messages[i][j:j+2] +" ")
                fw.close()

                
        
# key = "0x557cfb9c1c78b048ae02bf5c88bc781a"
# IV =  "0xb5e6886305720c08aed644c3dfc36cd4"
# SM4.CTR(key, IV, r"LB_Crypto_main\LB_Crypto\SM4CTR_input.txt", 0)
# SM4.ECB(key, "LB_Crypto_main\LB_Crypto\SM4ECB_input.txt",1)