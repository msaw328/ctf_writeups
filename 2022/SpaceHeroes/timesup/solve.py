val = 0xa4c570

a = 1
b = (val * 7 - 4) // 2
c = 1
def testfunc(a, b, c):
    return (a + b + c << ((a % b) & 0x1f)) // ((2 << (a & 0x1f) ^ 3) * c)

result = testfunc(a, b, c)

print(val)
print(result, hex(result))

print(hex(a), hex(b), hex(c))

from pwn import *

#s = process('./timesup')
s = remote('0.cloud.chals.io', 26020)

print(s.readuntil(b'>>> ').decode())

s.writeline('{} {} {}'.format(hex(a), hex(b), hex(c)).encode())

s.interactive()
