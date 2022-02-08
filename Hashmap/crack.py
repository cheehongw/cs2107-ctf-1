import itertools
from string import ascii_uppercase
from Crypto.Hash import SHA1

password1 = 'P@ssw0rd1!'
flagHash = '9d9eea545804f3a4edf7315c5325a4e55268420d'

keys = [''.join(i) for i in itertools.product(ascii_uppercase, repeat = 6)]

i = 0

for key in keys:
    i += 1
    toHash = str.encode('CS2107{' + password1 + '_' + key + '}')
    h = SHA1.new(data = toHash).hexdigest()
    
    if (h == flagHash):
        print(toHash)
        print(key)
        break

    if (i % 10000000 == 0): #rudimentary progress tracker
        print(i)
        print(h)

