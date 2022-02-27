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

### B.1 Elementary RSA (7 Points)
This is a textbook RSA. Given the modulus N, public exponent E, and ciphertext C, it is typically unfeasible to decipher C without the private key, D. To generate the private key D, we require the prime factors of N to calculate totient(N).

In this case, the prime factors can be found on factordb.com:

![image](https://user-images.githubusercontent.com/72195240/155871919-1536ee72-b337-49b7-97c0-7678cfdccfbc.png)

```python
totient = (p-1)*(q-1) #calculate totient(n)
d = pow(e, -1, totient) #d is the multiplicative inverse of (e mod totient(n))
result = pow(c,d, n) #result is c^d mod n

print(long_to_bytes(result)) #convert to bytes
```

**Flag: CS2107{n0t_s1mple_LiK3_aBc_bUt_siMp7E_l1ke_RSA}**

### B.2 Secret XOR Service (10 Points)

Looking at the source code reveals that this is a stream cipher. It uses random oracle (`os.urandom`) to generate a 32-byte long key. If the plaintext is longer than 32 bytes, the key is extended by repeating it. The plaintext is then XOR-ed with the key to generate the ciphertext.

The service accepts a phrase entered by the user and concatenates the phrase with the flag to form the plaintext, which is XOR-ed with the extended key. As such, we can insert a 64 hexadecimal long phrase (which is 32 bytes) of zeros to create a plaintext which is the flag padded with 32 bytes of 0 at the front.

When encrypted, the first 32 bytes of the ciphertext gives us the key since `k XOR 0 = k`.
![image](https://user-images.githubusercontent.com/72195240/155871936-862b3eba-e743-4ae0-9d8c-40aaaaeb1f0b.png)


The selected text in the image corresponds exactly to the secret key used. The remaining 54 hex characters corresponds to the XOR-ed flag.

With the key in hand, we can truncate the key to be 54 characters long and XOR it with the remaining ciphertext to retrieve the flag.
![image](https://user-images.githubusercontent.com/72195240/155871944-25601fb5-577f-439e-bc56-688fcbc5d849.png)


**Flag: CS2107{my_x0r_607_cr4ck3d}**

### B.3 Secondary RSA (12 Points)
This is an extension of __B.1 Elementary RSA__.

The flag is encrypted using 2048-RSA 3 times, with 3 different moduli (`n0`, `n1`, `n2`) like so:
> Ciphertext = RSA<sub>n2</sub>(RSA<sub>n1</sub>(RSA<sub>n0</sub>(plaintext)))

Performing a lookup on factordb, we find the 3 unique primes that are multiplied pairwise to give us `n0`, `n1`, `n2`.

We can now find the private exponents d0, d1, d2 for each moduli using the primes. To decrypt the ciphertext, apply the decryption in the opposite order that they were encrypted.

```python
n0 = p*q
n1 = q*r
n2 = p*r

PHI0 = (p-1)*(q-1)
PHI1 = (q-1)*(r-1)
PHI2 = (p-1)*(r-1)
d0 = pow(e, -1, PHI0)
d1 = pow(e, -1, PHI1)
d2 = pow(e, -1, PHI2)

res = pow(c,d2, n2)
res = pow(res,d1, n1)
res = pow(res,d0, n0)

print(long_to_bytes(res))
```

output:
```
b'With one exception, I can guarantee you that the shot you took when you applied to this institution is one you will never regret. I do not have to wait until the end of your life to tell you that. I speak from experience. Congratulations RSA class of 2021, on radically improving your chances in life. Go make the world a better place. I am so proud of you all. The flag is CS2107{b4d_tr1pLe_rSA_oWadi0_gR4dUaTe_Lo}\n'
```

**Flag: CS2107{b4d_tr1pLe_rSA_oWadi0_gR4dUaTe_Lo}** 

### B.4 Secret Base64 Service (12 Points)

Trying out some simple hexadecimal inputs such as `0000` or `FFFF` reveals that each 6-bit sequence is mapped to the wrong base64 character. As such, we need to get the mappings for each possible 6-bit sequence to the character used in the secret base64 service. While we could probe the service 64 times, a much better way is as shown:

1.	Concatenate all 2^6 bit patterns from 000000 to 111111 sequentially using a simple script, like so:
000000000001000010…...111110111111. 

2.	Pass this into a binary to hex converter (such as cyberchef) to receive the hex string representing this long sequence of bits 

3.	Pass the hexadecimal value into the FREE BASE64 SERVICE. The service returns an encoded string:
`njpO/AslmMHou4EerSLUtvgxTQJiaYyd2F+qfIc0wbXDZGBhPC3786R1kN9KWz5V`

4.	Each character in the string represents the 6-bit value corresponding to its position in the string. This is like a substitution cipher, and since we know what a normal base64 charset looks like, we can do:
`tr 'njpO/AslmMHou4EerSLUtvgxTQJiaYyd2F+qfIc0wbXDZGBhPC3786R1kN9KWz5V' 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' < Encodedflag.txt > decodedFlag.txt`

5.	And convert the decodedFlag.txt from base64 to ASCII using the normal base64 charset to get the flag.

**Flag: CS2107{HoW_AbOuT_CuSt0m_base64chArSeT}**

### B.5 AES Good AES Me (12 Points)

The key provided is 16 bytes long, or 128 bits. Together with the provided scheme image, the encryption scheme used is AES-128 in CBC mode.

<img src='/AES good AES me/scheme.png' width=500>

AES-128 uses block sizes of 128 bits, and the given plaintext and ciphertexts are 256 bits long. Thus, we can deduce that there are 2 blocks, p0 and p1, to be encrypted in our scenario.

First, in order to get `flag[1]`, we need to find out what is C<sub>0</sub>, but to do that, we have to find out what is the key first.
Based-off the scheme image, we can see that:
> Enc<sub>k</sub>(C0 ⊕ P1) = C1
>  -->	Dec<sub>k</sub>(C1) = C0 ⊕ P1
>  -->	Dec<sub>k</sub>(C1) ⊕ P1 = C0

Therefore, if we have the key, we can find out C<sub>0</sub>

Thankfully, the key is only missing 2 bytes, which effectively limits the key space size to 2 * 2<sup>8</sup>  = 512, which is very easily found through bruteforce:
```python
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
```
output:
```
c0: 3c8aabc2edfc8afe35f81dacff232a83
key is: b'6F738g9Zzc1S3j4g'
missing bytes: b'c1'      
```

With the key and c0 and p0 in hand, we can proceed to find `flag[1]`:
> flag[1] = Dec<sub>k</sub>(C0 ⊕ P0) 

**flag = flag[0] || flag[1] = CS2107{c1pH3r_BLoCk_ch4iN}**

### B.6 Unserialize Hash Length (15 Points)

Acknowledgements: https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks (hash_extender tool)

In this case, first note from the source code that the secret is concatenated with the data before it is hashed. As such, the MAC generated is vulnerable to a hash length extension attack. In this case, we can use the hash_extender tool to perform the calculation for us. From the manual of the hash_extender tool:
![image](https://user-images.githubusercontent.com/72195240/155871960-bdbc320a-2aa7-44e0-a479-a3b960ac6370.png)


In this case,
> d= original value which is stored in the users cookie
> s= original value of the signature cookie
> a= `%3Cx%3EO%3A4%3A%22User%22%3A2%3A%7Bs%3A15%3A%22%00User%00userlevel%22%3Bi%3A2107%3Bs%3A14%3A%22%00User%00username%22%3Bs%3A11%3A%22God%22%3B%7D`, which is copied from the last part of the users cookie with the level modified.
> f= SHA-256
> l= 32 bytes, as mentioned in the source code
![image](https://user-images.githubusercontent.com/72195240/155871967-953c77c5-770a-47dc-95de-da14c040080d.png)

With the new signature and message, we can replace the values in the original cookies.
![image](https://user-images.githubusercontent.com/72195240/155871970-bfcd2c57-4663-46f1-acb4-b2d4f3c79632.png)

Refresh the page with the cookies and we are done!
![image](https://user-images.githubusercontent.com/72195240/155871974-b3c67052-35f3-400e-9da7-3005c2744cdb.png)


### B.7 Secret AES Service (15 Points)

First identify that the service provided is in fact a padding oracle. As such we can perform a padding oracle attack on to decipher the ciphertext.
In this case, the ciphertext is 224 hexadecimals long, or 869 bits. Under AES-128-CBC, we can deduce that there are **seven** 128-bit blocks, c1 to c7.

To begin the attack, we need to find a better way to access the padding oracle other than to manually enter our guesses in the webpage. A simple function using the python requests library helps to achieve this:

```python
import requests
URL = "http://cs2107-ctfd-i.comp.nus.edu.sg:4004/"

def oracle(toTest):

    item = {'data': toTest}
    r = requests.post(url = URL, data = item)
    result = 'Successful' in r.text
    return result
```

We know that padding oracle attack is carried out between 2 consecutive cipher blocks. As such, define a function that accepts two ciphertext blocks. To crack the whole ciphertext, the final output would be:
![image](https://user-images.githubusercontent.com/72195240/155871983-7508aab2-a319-4d27-b096-a175c92327a6.png)


```
print(
    attack(cipher1, cipher2) +
    attack(cipher2, cipher3) +
    attack(cipher3, cipher4) +
    attack(cipher4, cipher5) +
    attack(cipher5, cipher6) +
    attack(cipher6, cipher7)
)
```

Within the attack function, perform the padding oracle algorithm to generate all 16 bytes of the block using the special padding scheme. Special care is to be taken with the final pair of ciphertext block, since there is a good chance that padding is applied to the last plaintext block. In this case, the plain text was padded with 8 bytes. 

Source code for the attack function is included in the respective challenge folder where this assignment document was submitted with.
