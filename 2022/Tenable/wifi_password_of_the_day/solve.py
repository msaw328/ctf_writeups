import random
import base64

from statistics import mode

from pwn import *

s = remote('0.cloud.chals.io', 28931 )

def encrypt_remote(data):
    s.read().decode('ascii') # read the "enter username" thing

    s.writeline(data.encode('ascii'))

    result = s.readline() # read resulting base64
    result = base64.b64decode(result)
    return result

ALPHABET = '_' + '}' + string.ascii_letters + string.digits # alphabet out of which the flag is most likely composed
IKNOW = 'flag{' # i know this part of the flag

# Since this is CBC and not CTR there is some padding work necessary
# The exploit leaks information through ciphertext length so
# it needs to make sure it crosses a boundary between blocks
# This function generates a padding with this property
# https://shainer.github.io/crypto/2017/01/02/crime-attack.html
# https://github.com/mpgn/CRIME-poc/blob/master/CRIME-cbc-poc.py
def adjust_padding():
    garb = ''
    found = []
    l = 0
    origin = encrypt_remote(garb + IKNOW + '~#:/[|/')
    while True:  
        enc = encrypt_remote(garb + IKNOW + '~#:/[|/')
        if len(enc) > len(origin):
            break
        else:
            l += 1
            garb = ''.join(random.sample(ALPHABET, k=l))
    return garb[:-1]

PADD = adjust_padding()

# buffer for found chars
found = ''

print('sofar: ', IKNOW + found)

# This is my understanding, but i may be wrong:
# assuming 'found' does contain some part of the flag that is
# later in the plaintext, then IKNOW + found + something will result in
# better compression than IKNOW + something + found, since in first
# case its a single long duplicate between two places, and in second case
# its two shorter duplciates. This type of check guards against false positives
# that just happen to be somewhere else in the plaintext and guarantee that
# the IKNOW part of the sequence is taken into account. Not sure though, must read up.
# https://github.com/mpgn/CRIME-poc/blob/master/CRIME-cbc-poc.py
while len(found) == 0 or found[-1] != '}':
    for c in ALPHABET:
        test1 = encrypt_remote(PADD + IKNOW + found + c + '~#:/[|/')
        test2 = encrypt_remote(PADD + IKNOW + '~#:/[|/' + found + c)
        print(bytes(PADD + IKNOW + found + c, 'ascii'), len(test1), len(test2))

        if len(test1) < len(test2): # if this stands, means char is probably correct, append
            found += c
            break

# This should be a flag by now
print(bytes(IKNOW + found, 'ascii'))
