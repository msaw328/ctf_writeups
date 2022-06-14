overfloat - 100 points, 214 solves

category: pwnable

original description:
    nc challenges.fbctf.com 1341
    Written by dana
    [download link]

downloaded files:
    overfloat - executable
    libc-2.27.so - custom libc

my files:
    overfloat_patched - executable patched with a jmp instruction to skip alarm()
    exploit.py - exploit script written in python using pwntools
    ghidra_decompilation/ - directory containing decompilation of functions from the binary

---- writeup ----
The executable called alarm() and set up a signal handler for SIGALRM called timeout()
which called exit() immediately. To counteract that i patched it in radare2 with
an unconditional jump and continued with new overfloat_patched binary.

It received input in a form of latitude/longitude pairs, finished by typing in "done"
when prompted for latitude. I found out using ghidra, that main() allocated an array of
12 floats (48 bytes) and passed it to a function called chart_course(). In chart_course(),
each line of input was read using fgets() so it was length checked, but later converted to
a float by atof(), and the float was appended to the array without any checks. That meant the
binary had a buffer overflow behind a layer of indirection, as the payload had to be input
in the form of float strings such as "12.3456".

I started writing a python script, beginning with a function called btf() (defined in exploit.py
on line 24) which used struct.unpack() to reverse atof(): given 4 bytes as an argument it
returned a float string that would be represented in memory by those 4 bytes after atof().
This way i could encode my payload 4 bytes at a time. I also wrote a function nextprompt()
(exploit.py line 30) which kept track of current prompt (used with pwntools process.recvuntil()).
Later i used these two in input_payload() (exploit.py line 43) which took a payload as a byte
string, split it into 4 byte packets, encoded each of them as a float string and input those.

Now that i had buffer overflow working and could control saved rip easily, i started looking
around for ROP gadgets and useful functions. Since i did not know if fbctf's servers had ASLR on,
i started by looking at whatever useful symbols i could find in the executable itself, as it had PIC
disabled. My first idea was to printf() with format "LAT[%d]: ", which would allow me to leak
value of the rsi register, but that only returned 4 bytes (%d format), and the whole address had
6 bytes. The first byte was constant 0x7f, but that still leaved a 1/256 chance to guess remaining 1 byte.

Since the printf() approach did not work i began reading about PLT and GOT. The way they work, GOT
gets populated with real address of the function at runtime by linker, after the function is first
called. I have realized that i can read bytes from memory using puts(), which i have access to
since its in PLT, cause it was used in the binary. I could pass any argument to it, since i have found
a "pop rdi; ret;" gadget by the end of __libc_csu_init() in the binary (second byte of pop r15 just
happens to be opcode for pop rdi, so the gadget is in the middle of another instruction).

I also needed to run more than one payloads on the binary, so i checked the address of main() to
call it as many times as i need, by finishing payloads with a main() call.

Finally, i noted down address of a GOT entry for printf() (as it was the area of memory that i wanted
to read from) and offsets of printf(), "/bin/sh" and system() relative from the base of libc. After
finding the address of printf() i could subtract the offset from it to get code base address.
Keep in mind that at the time of inserting the payload printf() GOT entry would already be populated
with a real address, as it was called by main() before.

During creation of first payloads i have realized that system() was segfaulting, which i suspected
was due to stack not being aligned to 16 byte boundary. Because of that i also used second half
of the "pop rdi; ret;" gadget, so just a "ret;" to align the stack before calling system() or printf().

All the gadgets/functions used are listen in exploit.py starting from the line 59.

First payload (exploit.py line 75) was meant to leak address of libc printf() from the GOT table,
so it looked like this:
    - 48 bytes of padding for buffer
    - 8 bytes of saved rbp (no need to preserve, just filled it with 'B's)
    - address of a ret; gadget to align the stack
    - address of a pop rdi; ret; gadget to load an argument into rdi
    - the argument, in this case address of a GOT printf() entry
    - address of puts()
    - another ret; to align the stack
    - call to main() so that we can input another payload afterwards

(I am not sure if all rets in my payload were needed, i just put them before segfaulting
function calls and it worked, guess it really was unaligned stack after all)

After calling input_payload() with the new crafted payload i have read the output and extracted
the leaked address from it (exploit.py line 84 and beyond), calculated libc code base by subtracting
the offset of printf() and calculated real addresses of "/bin/sh" and system() in the memory.
Sometimes the payload did not work, if the address just happened to have a null byte in it, as
puts() stops reading at null bytes, but it was very rare. Much higher chance of succeeding than
my previous printf() approach with its 1/256 chance to guess a random byte.

After getting all the needed addresses we can input second payload:
    - 48 bytes of padding
    - 8 bytes of rbp
    - pop rdi; ret; gadget to populate the argument
    - argument, here the address of "/bin/sh"
    - ret; gadget to align the stack
    - address of system()

Inputting second payload resulted in interactive shell. Remote obviously runs the unpatched version
of the binary, so running exploit.py on it still had the time limit due to alarm(), but it was
long enough to input 2 payloads and find a file /home/overfloat/flag on the server, which contained
the flag.

flag: fb{FloatsArePrettyEasy...}

---- thoughts ----
The libc that i found in downloaded archive was compiled for Ubuntu and trying to preload the executable
with it resulted in segfaults. It took me a long time to find out what was the cause. Always check what
system were libraries in tasks compiled for and have a Ubuntu VM with pwndbg installed ready for testing.

The challenge took me all day, even though most people solved it in first few hours, because i was
unaware of how PLT and GOT work. Understanding them is very useful when dealing with non-PIC
binaries as they can be used to bypass ASLR when combined with other vulnerabilities. Good to keep in mind.
