big_counter = 0

for i in range(0, 0x18):
    val = (i - (i >> 0x1f) & 1) + (i >> 0x1f)
    if val == 1:
        big_counter += 1
    print(str(i) + " : " + str(val))


