__author__ = 'rutger'
# https://gist.github.com/sekondus/4322469

import M2Crypto
import binascii
import sys

def get_cryptor( op, key, alg='aes_128_ecb', iv=None ):
    if iv == None:
        iv = '\0' * 256
    cryptor = M2Crypto.EVP.Cipher( alg=alg, key=key, iv=iv, op=op)
    return cryptor

def AESencode( key, plaintext ):
    cryptor = get_cryptor( 1, key )
    ret = cryptor.update( plaintext )
    ret = ret + cryptor.final()
    return ret

def AESdecode( key, ciphertext ):
    cryptor = get_cryptor( 0, key )
    ret = cryptor.update( ciphertext )
    ret = ret + cryptor.final()
    return ret

cache = {}

def getCipher(secret):
    if secret not in cache:
        iv = secret[:16]
        cache[secret] = AES.new(secret, AES.MODE_ECB, iv)

    return cache[secret]
