import binascii

def bytestring_to_hex(bytestring, sep=" ", prefix=""):
    hex_string = binascii.hexlify(bytestring).decode("ascii")
    hex_space_separated = sep.join([hex_string[i:i+2] for i in range(0, len(hex_string), 2)])
    return prefix + hex_space_separated

def bytes2int (b, byteorder="big"):
    return int.from_bytes(b, byteorder)

def int2bytes (i, length, byteorder="big"):
    return (i).to_bytes(length, byteorder)

def remove_leading_zero_bytes (b):
    while len(b) > 0 and b[0] == 0:
        b = b[1:]
    return b

def exp(b, e, m):
    result = 1
    b = b % m
    while (e > 0):
        if (e % 2 == 1):
            result = (result * b) % m
        e = e >> 1
        b = (b*b) % m
    return result
