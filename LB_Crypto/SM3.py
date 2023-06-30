class SM3:
    def __init__(self) -> None:
        pass
    const_num = pow(2, 32)

    @classmethod
    def shift(cls, x: int, num: int):
        """对整数的32位二进制表示进行循环左移，返回一个左移后的整数"""
        return ((x << num) | (x >> (32 - num))) % cls.const_num
    
    @classmethod
    def padding(cls, msg):
        """填充为512bit的倍数
        
        msg: 需要填充的十六进制字符串
        return msg_padding:  填充后的十六进制字符串
        """
        length = len(msg)
        num = length % 128
        if num == 112:
            msg += '8'   
            msg += '0'*127
        else:
            if num < 112:
                msg += '8'
                msg += '0'*(112 - num - 1)
            else:
                msg = msg + '8'
                msg += '0'*( 128 - num + 112 - 1)
        length_hex = hex(length*4)[2:].zfill(16)
        msg_padding = msg + length_hex
        return msg_padding

    @classmethod
    def extend(cls, M):
        """
        Args:
            M (str): 512比特消息（128个16进制数）

        Returns:
            _type_: 拓展后的分组W，W_ex
        """
        W = []
        W_ex = []
        for i in range(16):
            W.append(int( M[8 * i:8 * (i + 1)], 16))
        for i in range(16, 68):
            num = (cls.P1(W[i-16] ^ W[i-9] ^ (cls.shift(W[i-3], 15))) ^ cls.shift(W[i-13], 7) ^ W[i-6]) % cls.const_num
            W.append(num)
        for i in range(64):
            W_ex.append((W[i] ^ W[i+4]) % cls.const_num)
        return W, W_ex
    
    @classmethod
    def P1(cls, X):
        return (X ^ cls.shift(X, 15) ^ cls.shift(X, 23)) % cls.const_num

    @classmethod
    def P0(cls, X):
        return X ^ cls.shift(X, 9) ^ cls.shift(X, 17) % cls.const_num

    @classmethod
    def FF1(cls, a, b, c):
        return a ^ b ^ c

    @classmethod
    def FF2(cls, a, b, c):
        return (a & b) | (a & c) | (b & c)

    @classmethod
    def GG1(cls, e, f, g):
        return e ^ f ^ g

    @classmethod
    def GG2(cls, e, f, g):
        return (e & f) | ((~e) & g)

    @classmethod
    def round(cls, W, W_ex, V):
        
        a, b, c, d, e, f, g, h = [V[i] for i in range(8)]
        for i in range(64):
            if i <= 15:
                ss1 = cls.shift((cls.shift(a, 12) + e + cls.shift(0x79cc4519, i % 32)) % cls.const_num, 7)
                ss2 = ss1 ^ cls.shift(a, 12)
                tt1 = (cls.FF1(a, b, c) + d + ss2 + W_ex[i]) % cls.const_num
                tt2 = (cls.GG1(e, f, g) + h + ss1 + W[i]) % cls.const_num
                d = c
                c = cls.shift(b, 9)
                b = a
                a = tt1
                h = g
                g = cls.shift(f, 19)
                f = e
                e = cls.P0(tt2)
            else:
                ss1 = cls.shift((cls.shift(a, 12) + e + cls.shift(0x7a879d8a, i % 32)) % cls.const_num, 7)
                ss2 = ss1 ^ cls.shift(a, 12)
                tt1 = (cls.FF2(a, b, c) + d + ss2 + W_ex[i]) % cls.const_num
                tt2 = (cls.GG2(e, f, g) + h + ss1 + W[i]) % cls.const_num
                d = c
                c = cls.shift(b, 9)
                b = a
                a = tt1
                h = g
                g = cls.shift(f, 19)
                f = e
                e = cls.P0(tt2)
        V = [V[0] ^ a, V[1] ^ b, V[2] ^ c, V[3] ^ d, V[4] ^ e, V[5] ^ f, V[6] ^ g, V[7] ^ h]
        return V


    @classmethod
    def digest(cls, message, mode=0, modeee=0):
        """
        :param msg: the message you wanna hash (a string or bytes)
        :param mode: 1 for file operation   0 default 
        :return: the hash value of the message (a string)
        """
        if modeee == 0: 
            message_UTF = message.encode('utf-8')
            message = message_UTF.hex()
        #填充
        message_padding = cls.padding(message)
        # 分成512bit一组，按组处理 
        klen = len(message_padding)//128
        message_group = []
        for i in range(klen):
            message_group.append(message_padding[128*i:128*(i+1)])
        
        V = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
        for i in range(klen):
            W, W_ex = cls.extend(message_group[i])
            V = cls.round(W, W_ex, V)
        message_digest = ''
        for i in range(8):
            message_digest += hex(V[i])[2:].zfill(8)
        if mode == 1:
            with open('LB_Crypto_main\LB_Crypto\SM3_output.txt', 'w') as fw:
                fw.writelines(message_digest)
            fw.close()
            return "已将hash值写入SM3_output.txt"
        return message_digest

 