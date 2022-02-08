from Crypto.Cipher import AES
import requests

cipher1 = 'b12c3f6a001ab28eb3dafbfa2d634dc2'
cipher2 = '0419370e98feeedfdb2d679bddf49f30'
cipher3 = '47525527b5dbf890ae7bb8edcbc33b82'
cipher4 = 'b652a8d4b7d6dedb343b605e0d340d48'
cipher5 = 'ac0b5f7190fe1bc7156962f88367d098' 
cipher6 = 'c60e7e1815dbc964a5784a7f908142bb'
cipher7 = '3c5f80f9917b982de84f6da930d6fe85'

URL = "http://cs2107-ctfd-i.comp.nus.edu.sg:4004/"

def oracle(toTest):

    item = {'data': toTest}
    r = requests.post(url = URL, data = item)
    result = 'Successful' in r.text
    return result

def attack(c0, c1):
    # since we are modifying c0 byte-by-byte, we shall use an array of size 16 to hold the 16 bytes.
    # it is easier (for me) to modify the string byte-wise this way
    placeholder = [c0[i:i+2] for i in range(0, len(c0), 2)]  #put c0 here

    # intermediate value that we are trying to find. Represents decrypt_K(c1) in the scheme diagram.
    intermediate = [None] * 16 

    SKIP_PAD = 7 # the original ciphertext was padded with 8 bytes. So this program would fail at round 7 (15-8)
                 # Other cipherblock pairs have 0 padding so it doesn't affect with what we do

    for j in range(15, -1, -1):

        CURR = placeholder[j] #for comparing the final block pair only
        print('CURRENT ROUND {0}'.format(j))

        for k in range(15-j):
            k = k+1
            if (k == 0) :
                continue
            else:
                placeholder[j+k] = hex(int(intermediate[j+k], 16) ^ (k+1))[2:].zfill(2)       

        for i in range(255): #test all bytes for a particular position
            change = hex(i)[2:].zfill(2)
            placeholder[j] = change
            toTest = ''.join(placeholder) + c1
            result = oracle(toTest)

            # (j == SKIP_PAD or change != CURR) to handle edge cases if the 
            # last two block pairs are provided as arguments to the function, otherwise it is not needed
            if result and (j == SKIP_PAD or change != CURR):

                intermediate[j] = hex(i ^ 1)[2:].zfill(2) #build up the correct intermediate value
                print('success! {0}'.format(intermediate[j]))
                print('Current Round {0}: {1}'.format(j,''.join(placeholder)))
                break

    print('FINAL {0}'.format(''.join(intermediate)))
    return bytes.fromhex(hex(int(''.join(intermediate),16) ^ int(c0, 16))[2:])

print(
    attack(cipher1, cipher2) +
    attack(cipher2, cipher3) +
    attack(cipher3, cipher4) +
    attack(cipher4, cipher5) +
    attack(cipher5, cipher6) +
    attack(cipher6, cipher7)
)