unary - 182 points, 20 solves

category: pwnable

original description:
    Which operation do you prefer?
    nc 66.172.27.144 9004
    [download link]

downloaded files:
    unary - executable
    libc-2.27.so - custom libc

my files:
    main.c - decompilation of function main() from ghidra
    ope.png - disassembly of symbol ope[]
    solver.py - exploit written in python using pwntools

---- writeup ----
The binary takes two inputs from user, first chooses what operation to perform, second takes
the value to perform the operation on. If chosen operation is "0" then program exits.

Custom libc didn't work on my Arch, so i assumed it was compiled for Ubuntu and i worked on
the exploit on a VM.

Started with decompilation in ghidra. After taking a look at main() we can see that operations
are actually different functions with the same signature, and ope[] is an array of function pointers,
pointing to them (i had to figure it out myself, as ghidra was kind of lost and the decompiled code
was weird, main.c includes my edits). What's interesting is that input from user is directly used as index 
to the array ope[] without any validation beforehand, which allows us to call any function as long as we can calculate
its offset from the ope[] symbol and not only that, but we can actually pass it some arguments and modify
local_2c on stack, as its address is passed as 2nd argument (as long as we find functions with correct signatures).

Using checksec on binary showed that it does not have a stack canary, so it's vulnerable to buffer
overflows and, in addition to calling any function using the ope[] call, we can also change the flow of
code completely by overriding saved RIP on stack. This allows us to enter a ROP chain after some initial field work.

I assumed that ASLR is turned on on the server (and it was), which means that addresses of libc are still
randomized, as all shared objects are automatically compiled with PIE on, so if we wanted to use any functions
not in PLT we needed to leak data.

The only functions in PLT were puts(), setbuf(), __printf_chk(), __isoc99_scanf() and exit(), so it was
obvious that i'd need to use functionality from libc, namely i decided to aim for system("/bin/sh") as i found
both the function and the string in the custom libc.

First part was to make a handy function to calculate addresses as offsets relative from ope[]. This is what
function "addr_to_op()" defined on line 12 in solver.py does. The address of ope[] (0x600e00) is hardcoded as,
again, the executable itself is not PIE so it's placed at the same address in memory every time.

The flow of the program is as follows: first it reads an integer using scanf with format "%d" which is used
as index to ope[] array, this is where the offset to a function we want to call calculated with addr_to_op() goes.
Second input is another integer, which this time serves as the first argument to the function. While in case of operations
this was treated as an integer on which the operation was performed, the function we call may treat it as anything, even a pointer.
Both values have to be put in as decimal values due to format being "%d" not "%x" so we wont be using hex() for output
in the python script.

In lines 17-26 in solver.py i have noted down addresses of various useful things found in the binary itself
(which means their addresses can be hardcoded): 3 functions, 2 format strings ("%d" and "%s") and 2 ROP gadgets.

Now, to the actual exploit:
First Stage (starting line 31 in solver.py) sends offset to puts()@plt as first input. Because puts expects
char* pointing to data to be printed it will treat our second input as a pointer, and will not modify local_2c
(since it only takes 1 argument - signature is int puts(const char* s)).

As second input, we send the address of GOT entry for setbuf(). We could have chosen any GOT entry which points into libc,
so any libc function which has been previously used by the binary. This time we pass the address without addr_to_op(),
since it's passed directly as the function argument, without the ope[] translation. This all happens in lines 31-37 in solver.py

Afterwards, in line 39 in solver.py we read what puts() have written, which is the address in GOT pointing into libc
to setbuf() function. Since writing ends at null bytes we have to append 2 additional bytes at the end (addresses are usually
only 6 bytes long, instead of full 8) and sometimes there is a chance that it wont work, if the address just happens to have a
null byte in it, but it is very rare for it to happen.

Once we struct.unpack() output from puts as a Pointer ("P" argument to unpack(), line 40) we can subtract from it the offset
of setbuf() in libc. We can check the offset since we have a local copy of libc used. After line 44 we have leaked libc base address.

Second Stage (starting line 55 in solver.py) builds a ROP chain payload. We have 2 gadgets: pop rdi and ret, and a single ret.
Single ret allows us to align the stack before taking some function calls so that certain instructions which require stack to
be aligned to 16 byte boundary dont segfault. Pop rdi and ret is obviously used to pop an argument for our system() call.
Additionally, we calculate actual address of system() and "/bin/sh" based on leaked libc base. The ROP chain is built on line 66
and it looks like this:

padding (length found by trial and error in gdb) -> single ret to align the stack -> pop rdi; ret; -> address of "/bin/sh" (gets
popped into rdi by previous step) -> address of system()

Third Stage
To send the ROP chain we will overwrite local_2c and all other stack variables using a scanf() call with "%s" format.
Just like in Stage One we calculate offset of scanf() from ope[] and pass it as first input, and then pass the address
of format string "%s" as second input. 2nd argument to scanf() is obviously address of the buffer for the string being read,
so bytes will be written to 4 bytes of local_2c and overflow onto other variables and eventually the saved RIP.
Scanf also has this nice property that it does not stop at null bytes, so we do not have to xor our payload with anything.
All that happens in lines 67-73

On line 76 we send the actual ROP chain to our scanf("%s") call.

Afterwards, last thing to do is to exit from main, to do this we select index 0 when choosing operation (first input, line 82).
This results in interactive shell, and we can read file flag.txt placed in current directory we are in.

flag: SUSEC{0p3r4710n_w17h_0n1y_1_0p3r4nd}

---- thoughts ----
This challenge reminds me a lot of a challenge "overfloat" from fbctf 2019 (i also have a writeup for it in this repo).
The twist in overfloat for sending a payload was that it had to be encoded as floating point numbers, while here we're
able to execute code relative to some address.

Back then i did not really know how PLT and GOT worked and it took me entire day to learn that and solve overfloat, so i'm glad that everything
i have learned from overfloat allowed me to solve unary so much quicker (including working in a Ubuntu VM, helps a lot to have one ready).
