#!/usr/bin/env python3
from Crypto.Util.number import *

flag = "CS2107{????????????????????????}"

def is_prime(n):
    return True

def encrypt():
    with open('../transcript.txt', 'rb') as f:
        flag = f.read()

    p, q, r = (getPrime(2048), getPrime(2048), getPrime(2048))

    assert is_prime(p)
    assert is_prime(q)
    assert is_prime(r)

    ns = [q * r, p * q, p * r]
    e = 65537
    c = bytes_to_long(flag)

    for n in ns:
        c = pow(c, e, n)

    with open('secret.txt', 'w') as f:
        f.write(f'ns: [{ns[0]},\n {ns[1]},\n {ns[2]}]\n')
        f.write(f'c: {c}\n')

if __name__ == "__main__":
    encrypt()
