from m import *
from random import *
import math

# Step 1
def message_hash(m):
    msg = m
    msg_bi = ""
    for char in msg:
        a = dectobin(char)
        msg_bi +=a

    msg_bi_len = len(msg_bi)
    pad_msg = msg_bi + "1"

    if len(pad_msg) > 448:
        b = math.ceil(len(pad_msg)/512)
        b = b*512 - 64 - len(pad_msg)
    else:
        b = 512 - 64 - len(pad_msg)

    for i in range(b):
        pad_msg += "0"

    msg_len = len(msg_bi).to_bytes(8, byteorder='little')
    msg_len = ''.join(format(byte, '08b') for byte in msg_len)
    final_msg = pad_msg+msg_len

    msg_div = msgtoblocks(final_msg)
    msg_block = blocktowords(msg_div)

    A,B,C,D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    A1,B1,C1,D1 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

    K = [3614090360, 3905402710, 606105819, 3250441966, 4118548399, 1200080426, 2821735955, 4249261313, 
        1770035416, 2336552879, 4294925233, 2304563134, 1804603682, 4254626195, 2792965006, 1236535329, 
        4129170786, 3225465664, 643717713, 3921069994, 3593408605, 38016083, 3634488961, 3889429448, 
        568446438, 3275163606, 4107603335, 1163531501, 2850285829, 4243563512, 1735328473, 2368359562, 
        4294588738, 2272392833, 1839030562, 4259657740, 2763975236, 1272893353, 4139469664, 3200236656, 
        681279174, 3936430074, 3572445317, 76029189, 3654602809, 3873151461, 530742520, 3299628645, 
        4096336452, 1126891415, 2878612391, 4237533241, 1700485571, 2399980690, 4293915773, 2240044497, 
        1873313359, 4264355552, 2734768916, 1309151649, 4149444226, 3174756917, 718787259, 3951481745]

    l = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    row , col = msg_block.shape
    for i in range(col):
        for j in range(row):
            s = bintodec(msg_block.iloc[j,i])
            s = int.from_bytes(s.to_bytes((s.bit_length() + 7) // 8, 'little'), byteorder='big')
            msg_block.iloc[j,i] = s


    for i in range(col):
        for p in range(64):
            if p < 16:
                f = (B & C) | ((~B) & D)
                # print(f)
                g = p%16
            elif p < 32:
                f = (D & B) | ((~D) & C)
                g = (5*p + 1) % 16
            elif p < 48:
                f = B ^ C ^ D
                g = (3*p + 5) % 16
            else:
                f = C ^ (B | (~D))
                g = (7*p) % 16

            f = (f + A + K[p] + msg_block.iloc[g,i]) & 0xFFFFFFFF
            A = D
            D = C
            C = B
            B = (B + leftrotate(f, l[p])) & 0xFFFFFFFF

    A = (A + A1) & 0xFFFFFFFF
    B = (B + B1) & 0xFFFFFFFF
    C = (C + C1) & 0xFFFFFFFF
    D = (D + D1) & 0xFFFFFFFF


    B = B * (2 ** 32)
    C = C * (2 ** 64)
    D = D * (2 ** 96)

    hash = A+B+C+D

    hash = hash.to_bytes(16, byteorder='little')
    hash = '{:032x}'.format(int.from_bytes(hash, byteorder='big'))
    return hash