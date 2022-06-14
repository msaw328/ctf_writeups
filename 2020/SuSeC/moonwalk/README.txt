moonwalk - 161 points, 24 solves

category: baby/reverse

original description:
    After seeing the iconic Moonwalk, Covid19 wants to use its spike proteins
    to do the walk on the lung cells of infected people.
    Could it succeed in this evil endeavor?
    [download link]

downloaded files:
    moonwalk - executable

my files:
    main.c - source code of main() reversed with ghidra
    firstloopover24.py - this and other python scripts explained in the writeup
    firstcheck4and0f.py
    secondif.py
    bufferconstructor.py - builds and prints 4 parts of the flag

---- writeup ----
I decompiled the binary with ghidra, and renamed some variables in main().

The most important variable is flagbuffer, a char* which points to a malloc'ed buffer of size 0x29 (41) in line 79 of main.c,
there are also few other buffers for additional data and few counters/iterators for various loops.

First step is to fill a buffer[] filled with 24 characters, which then gets iterated over, and, according to a pretty big
if statement, gets its elements copied to flagbuffer. Analysis of the condition on line 108 in main.c led me to believe it
just returns 1 for every odd number and 0 for every even number (number being the counter_0x18 variable). To test that, i wrote
a python script "firstloopover24.py", which confirmed it. The if statement on line 116 in main.c relies on the value of
variable "final_check_gt_5e4cf66f" (which, despite its name, is just another counter that i thought was special when naming it, because
it is checked to be greater than 0x5e4cf66f in the very end) which gets modified by the first loop over buffer_32[], based on how many
values pass the if statement on line 108. Apparently the only passing value for the check on line 116 is number 12
(checked with script "secondif.py"), so that means that every character on index that passes the condition on line 108 has to also
pass the condition on line 107 (they are logical AND'ed), so it has to be equal to a certain value from the buffer.

Lines 5-36 in bufferconstructor.py are the result of this part of work, they construct a slice of the flag.

Later comes a big chunk of code (lines 120 - 146) that produces an artificial delay of 20 minutes and an animation of a loading bar in terminal
(which looks pretty sweet, not going to lie). I did not analyze this part of code much, because a few glances made me believe that it has
no effect on any state that would matter in later parts of the code and was there merely to annoy. I would have patched it away with radare2
but in the end i managed to construct the flag using nothing but python scripts, without actually running the binary so i had no problem with it.

Next part is a big if on line 155 in main.c (i will skip buff_weird[] part for now) which just XOR's two characters at a time from flagbuffer,
i am sure there are plenty of smart ways to solve it, but i just decided to brute force it with secondif.py, the result for fb[0] = 'y' looked like
"you will" and no other option seemed to make sense.

Lines 40-49 in bufferconstructor.py are the result of this part of work.

NOW comes weirdbuffer (called buff_weird[] in main.c). It's a buffer that gets filled with certain bytes in 2 parts of code (lines 149-153 and 169-173)
and then strncmp'ed with a certain offset from flagbuffer* in line 174, pretty simple stuff.

Lines 53-62 in bufferconstructor.py are the result.

Last part of the flag comes from an if and a XOR operation in lines 181 and 182 in main.c, resulting part of the flag will be equal to the XOR of those two
constant numbers.

Line 66 in bufferconstructor.py is the result of this part of work, and also it doesn't even print it in proper order because i had the flag ready anyways.

According to the task the result was not going to have the SUSEC{} part around it, we were supposed to add it ourselves.

flag: SUSEC{y0u_w1l|_w4lk_wh3n_1t_1s_7ime_t0_w4lk;)}

---- thoughts ----
At first i was intimidated by the amount of if statements and variables in code, but turns out most of them
were just fillers and didn't actually change the value of flag. Never get scared of big code just because it is big.
