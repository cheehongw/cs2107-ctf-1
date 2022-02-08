from Crypto.Cipher import AES

c1 = bytes.fromhex('0df67cc18cdfc7f7605596e159d1102d')
p1 = '6b656420657665727977686572656565'
key0 = b'6F738g9Zz'
key2 = b'S3j4g'

for i in range(0xffff):

    key1 = bytes.fromhex(hex(i)[2:].zfill(4))
    key = key0 + key1 + key2
    
    cipher = AES.new(key, AES.MODE_ECB)
    d1 = cipher.decrypt(c1)
    
    c0_candidate = hex(int(d1.hex(),16)^int(p1,16))[2:].zfill(32)

    if (c0_candidate[6:8] == 'c2' and c0_candidate[28:30] == '2a' and c0_candidate[18:20] == 'f8'):
        print('c0: %s' % c0_candidate)
        print('key is: %s' % key)
        print('missing bytes: %s' % key1)
    
    
    
