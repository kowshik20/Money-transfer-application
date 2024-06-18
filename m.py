import pandas as pd

# Decimal to binary
def dectobin(n):
    a = ""
    for k in n:
        b = []
        if not isinstance(k, int):
            k = ord(k)

        while k != 0:
            rem = k % 2
            b.append(rem)
            k = k // 2

        while len(b) < 8:
            b.append(0)
        b.reverse()

        for digit in b:
            a += str(digit)

    return a


# Binary to Decimal

def bintodec(n):
    res = 0
    length = len(n)-1
    for i in n:
        res = res + int(i)*2**length
        length -= 1

    return res

# Decimal to Hexa Decimal

def dectohex(n):
    hexavalues = "0123456789abcdef"
    a = ""
    while n != 0:
        rem = n % 16
        n = n // 16
        if rem > 9:
            a = a + hexavalues[rem]
        else:
            a = a + str(rem)

    while len(a) < 8:
        a = a + "0"

    a = a[::-1]
    return a


# Hexa DEcimal to Decimal
def hextodec(n):
    hexavalues = "0123456789abcdef"
    decimal = 0
    length = len(n) - 1
    for i in n:
        if isinstance(i, str):
            if i in hexavalues:
                result = hexavalues.index(i)
                decimal = decimal + int(result) * 16 ** length
                length -= 1
        else:
            decimal = decimal + int(i) * 16 ** length
            length -= 1

    return decimal



# Conversion of Hexadecimal to Binary

def hextobin(n):
    hexavalues = "0123456789abcdef"
    result = []
    for i in n:
        if isinstance(i, str):
            if i in hexavalues:
                result.append(hexavalues.index(i))
        else:
            result.append(i)

    a = ""
    for k in result:
        b = []

        while k != 0:
            rem = k % 2
            b.append(rem)
            k = k // 2

        while len(b) < 4:
            b.append(0)
        b.reverse()

        for digit in b:
            a += str(digit)

    return a


# Binary to Hexa Decimal

def bintohex(n):
    hexavalues = "0123456789abcdef"
    a = []
    b = ""
    for i in range(len(n)):
        if i % 4 == 3:
            b = b + n[i]
            a.append(b)
            b = ""
        else:
            b = b + n[i]

    hexvalue = ""

    for i in range(len(a)):
        s = bintodec(a[i])
        hexvalue = hexvalue + hexavalues[s]

    return hexvalue


# Division of Message into 512 Blocks

def msgtoblocks(n):
    ms = []
    a = ""
    chunk_size = 512
    for i in range(len(n)):
        a = a + n[i]
        if (i + 1) % chunk_size == 0:
            ms.append(a)
            a = ""

    return ms


# Division of Block into 32bits of 16 words

def blocktowords(n):
    # word = []
    max_chunk_size = 32
    df = pd.DataFrame(data=None, columns=[f'Block {i + 1}' for i in range(len(n))],
                      index=[f'Word {i}' for i in range(16)])

    for i in range(len(n)):
        binary_string = n[i]
        for j in range(0, len(binary_string), max_chunk_size):
            chunk = binary_string[j:j + max_chunk_size]
            # word.append(chunk)
            df.iloc[j // max_chunk_size, i] = chunk

    return df


def leftrotate(z, c):
    c = int(c)
    a = int(z * (2**c))
    s = 32-c
    b = int(z / (2**s))
    c = a | b
    return c