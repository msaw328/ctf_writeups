fb = [ ord(c) for c in " " * 9 ]

def makebuf(c):
    fb[0] = c
    fb[1] = 0x49 ^ fb[0]
    fb[2] = 0x45 ^ fb[1]
    fb[3] = 0x2a ^ fb[2]
    fb[4] = 0x28 ^ fb[3]
    fb[5] = 0x46 ^ fb[4]
    fb[6] = 0x5d ^ fb[5]
    fb[7] = 0x10 ^ fb[6]
    fb[8] = 0x23 ^ fb[7]

for c in range(ord('0'), ord('z') + 1):
    makebuf(c)
    print(chr(c) + " : " + "".join([ chr(asc) for asc in fb ]))
