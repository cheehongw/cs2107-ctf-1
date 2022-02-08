#!/usr/bin/env python3
import os

FLAG = open('flag.txt','rb').read()

def xor(a, b):
    return bytes([i^j for i,j in zip(a,b)])

def extend_key(key, size):
    return key*(size//len(key)) + key[:size%len(key)]

def encrypt(data):
    key = os.urandom(32)
    keystream = extend_key(key, len(data))
    encrypted = xor(keystream, data)
    return encrypted.hex()

if __name__ == "__main__":
    print("\n===== MY SECRET XOR SERVICE =====\n")
    plaintext = input('Enter your favourite phrase (in hex):  ').strip()
    try:
        plaintext = bytes.fromhex(plaintext) + FLAG
    except:
        print('Error: The input must be a valid hexadecimal string')
        exit(0)
    ciphertext = encrypt(plaintext)
    print("Here is your encrypted result (in hex):", ciphertext)
