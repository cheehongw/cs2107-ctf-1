# CS2107 CtF Assignment 1 Write Up

This document contains the write-up for the first CtF conducted during CS2107 AY21/22 Sem 1 as part of Assignment 1.

### A.1 Secret String (5 Points)
We are given a hexadecimal, which we are told that it is in binary format. The binary string is likely an ASCII/UTF-8 encoding of the flag. Thus, putting it through a hex-to-binary-to-UTF8 converter gives us the flag.

The following is a screenshot from CyberChef (https://gchq.github.io/CyberChef/), a useful online tool that can perform conversions between various encoding formats with ease. CyberChef have been used extensively to debug and do simple conversions for subsequent challenges.

<image width= 600 src="https://user-images.githubusercontent.com/72195240/153028849-5909c585-29f1-4b53-a7e0-43c41fe0149d.png"/>


### A.2 Hashlet (5 Points)
Run `md5sum existence.txt` on the terminal in the same directory as existence.txt

**Flag: CS2107{e236a845daaf9791e159f5b302d42b46}**


### A.3 Hashmap (7 Points)
`Password_1` is hashed with SHA-1, and when cracked with online tools, gave us the first half of the password. Turns out `Password_1` is a commonly used password and the hash is rather well known.

<image width=400 src="https://user-images.githubusercontent.com/72195240/153028879-35e3e4ed-8c44-4c2a-8199-0603368bedde.png"/>

`Password_2` is some possible 6-character string between `AAAAAA` to `ZZZZZZ`. The key space size is about 26<sup>6</sup> ≈ 2<sup>29</sup>, thus it’s possible to be brute forced by a simple script by simply iterating through all the possible values and checking if the generated hashes match the flag’s hash.

```python
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
```

**Flag: CS2107{P@ssw0rd1!_BRUTED}**
