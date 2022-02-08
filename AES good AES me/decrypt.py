from Crypto.Cipher import AES

c0 = bytes.fromhex('3c8aabc2edfc8afe35f81dacff232a83')
p0 = '492068617665206265656e20626c6f63'
key = b'6F738g9Zzc1S3j4g'
f0 = b'c1'

cipher = AES.new(key, AES.MODE_ECB)

d0 = cipher.decrypt(c0)

flag1 = hex(int(d0.hex(),16)^int(p0,16))[2:].zfill(32)

print(f0 + bytes.fromhex(flag1))
