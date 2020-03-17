import sys

buffer_flag = list([ ord(c) for c in " " * 0x28 ])

buffer_32 = list([ ord(c) for c in " " * 32 ])
buffer_32[0] = 0x70
buffer_32[1] = 0x77
buffer_32[2] = 0x6e
buffer_32[3] = 0x34
buffer_32[4] = 0x77
buffer_32[5] = 0x6c
buffer_32[6] = 0x69
buffer_32[7] = 0x6b
buffer_32[8] = 0x37
buffer_32[9] = 0x5f
buffer_32[10] = 0x65
buffer_32[11] = 0x77
buffer_32[12] = 0x76
buffer_32[13] = 0x68
buffer_32[14] = 0x6e
buffer_32[15] = 0x33
buffer_32[16] = 0x75
buffer_32[17] = 0x6e
buffer_32[18] = 0x62
buffer_32[19] = 0x5f
buffer_32[20] = 0x37
buffer_32[21] = 0x31
buffer_32[22] = 0x30
buffer_32[23] = 0x74

# 1st check
big_counter = 0
for i in range(0, 24):
    if i % 2 == 1:
        buffer_flag[big_counter + 9] = buffer_32[i]
        big_counter += 1

# 2nd check - brute force secondif.py

fb = buffer_flag
fb[0] = ord('y')
fb[1] = 0x49 ^ fb[0]
fb[2] = 0x45 ^ fb[1]
fb[3] = 0x2a ^ fb[2]
fb[4] = 0x28 ^ fb[3]
fb[5] = 0x46 ^ fb[4]
fb[6] = 0x5d ^ fb[5]
fb[7] = 0x10 ^ fb[6]
fb[8] = 0x23 ^ fb[7]

# 3rd weirdbuffer

fb[0x1d + 9] = ord(')')
fb[0x1d + 0] = ord('_')
fb[0x1d + 8] = ord(';')
fb[0x1d + 1] = ord('t')
fb[0x1d + 7] = ord('k')
fb[0x1d + 2] = ord('0')
fb[0x1d + 6] = ord('l')
fb[0x1d + 3] = ord('_')
fb[0x1d + 5] = ord('4')
fb[0x1d + 4] = ord('w')

# 4th check

print((0x20c44eba3078d09c ^ 0x45a9278d6f0be1c3).to_bytes(8, byteorder='little'))

sys.stdout.write("".join([ chr(asc) for asc in buffer_flag ]))
