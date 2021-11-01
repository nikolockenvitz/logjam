from Cryptodome.Cipher import AES, DES, DES3
import hashlib

from utils import *

def encrypt_aes_cbc(key, m, iv=None):
    return encrypt_cbc(AES, key, m, iv)

def decrypt_aes_cbc(key, c, iv):
    return decrypt_cbc(AES, key, c, iv)

def encrypt_des_cbc(key, m, iv=None):
    return encrypt_cbc(DES, key, m, iv)

def decrypt_des_cbc(key, c, iv):
    return decrypt_cbc(DES, key, c, iv)

def encrypt_3des_ede_cbc(key, m, iv=None):
    return encrypt_cbc(DES3, key, m, iv)

def decrypt_3des_ede_cbc(key, c, iv):
    return decrypt_cbc(DES3, key, c, iv)

def encrypt_cbc(alg, key, m, iv=None):
    cipher = alg.new(key, alg.MODE_CBC, iv)
    data = tls_pad(m, alg.block_size)
    c = cipher.encrypt(data)
    return cipher.iv, c

def decrypt_cbc(alg, key, c, iv):
    cipher = alg.new(key, alg.MODE_CBC, iv)
    data = cipher.decrypt(c)
    m = tls_unpad(data, alg.block_size)
    return m

def tls_pad(data, block_size):
    padding_length = block_size - len(data)%block_size
    padding_byte = int2bytes(padding_length-1, 1)
    return data + padding_byte * padding_length

def tls_unpad(data, block_size):
    if (len(data) == 0 or len(data)%block_size):
        return Exception("Wrong padding")
    padding_length = data[-1] + 1
    if (padding_length > len(data) or data[-padding_length:] != int2bytes(padding_length-1, 1) * padding_length):
        raise Exception("Wrong padding")
    return data[:-padding_length]

def hash_sha1(bytestring):
    return _hash(bytestring, hashlib.sha1)

def hash_md5(bytestring):
    return _hash(bytestring, hashlib.md5)

def hash_sha256(bytestring):
    return _hash(bytestring, hashlib.sha256)

def _hash(bytestring, function):
    h = function()
    h.update(bytestring)
    return h.digest()
