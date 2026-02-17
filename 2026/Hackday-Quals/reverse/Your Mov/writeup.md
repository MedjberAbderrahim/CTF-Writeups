# **Your Mov - Reverse Engineering Challenge Writeup**

## **Challenge Overview**

![Screenshot of Challenge](./assets/0.png)

- **Category**: Reverse Engineering
- **Synopsis**: A heavily MOV-obfuscated x86 32-bit binary that validates user input in two distinct stages. The challenge demonstrates advanced code obfuscation techniques and requires combining static analysis with dynamic behavioral analysis to extract the flag. The flag format is `HACKDAY{SHA256-HASH}`.

- **Written by**: **Spinel99** of **Underr00ted**

- **Event**: HackDay 2026 - Qualifications (Academic Only)
- **Event Link**: https://ctftime.org/event/3038
- **Final Points**: 304 out of 500
- **Tagged Difficulty**: Hard

- **Binary Details**:
    - Type: 32-bit ELF, stripping + MOV-Obfuscation makes static analysis nearly impossible:
```bash
your_mov: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, stripped
```

## **Understanding MOV Obfuscation**

### **What is MOV Obfuscation?**

MOV obfuscation is a powerful code obfuscation technique that implements arbitrary computation using only `MOV` instructions. This technique is based on the principle that nearly all computational operations can be implemented using memory access patterns and table lookups, without relying on traditional arithmetic or logical instructions.

The core idea is to:
1. **Pre-compute lookup tables** containing results of operations
2. **Use MOV instructions** to index into these tables based on input operands
3. **Extract the result** from the lookup table via another `MOV` instruction

### **Why is MOV Obfuscation Effective?**

- **Semantically opaque**: Disassemblers show only `MOV` instructions, making the actual computation logic invisible (IDA ,early killed me with its decompilation)
- **Control flow preserved**: The original control flow remains intact, but its purpose is hidden
- **Performant**: Lookup tables are faster than emulating operations with conditional jumps
- **Difficult to analyze**: Reversers cannot easily determine what the code is doing without understanding the table structure (again, IDA nearly took my life)

### **References and Tools**

For deeper understanding of MOV obfuscation and how to implement or analyze it, check out these resources:

- **MOV Obfuscator Repository**: [GitHub Link](https://github.com/xoreaxeaxeax/movfuscator)
  - The seminal work on MOV-based obfuscation, implementing a complete C compiler that outputs only `MOV` instructions

- **MOV De-Obfuscator Repository**: [GitHub Link](https://github.com/leetonidas/demovfuscator)
  - A generic way of recovering the control flow of the original program from movfuscated binaries

- **Further References:**
    - `MOV` is Turing-complete: [Link](https://drwho.virtadpt.net/files/mov.pdf)
    - `MOV` is Turing-complete [Paper Implementation]: [Link](https://leetarxiv.substack.com/p/mov-is-turing-complete-paper-implementation)

## **AI & ChatGPT PRO**

Shoutout to the creator of this challenge, for its great quality, it actually couldn't be solved using ChatGPT PRO, which is a feat not many medium difficulty reverse engineering CTF Challenges can claim.

This is what made me like the challenge even more, it forced me to think again and reverse engineer like the days of the long-gone pre-AI era, anyway now let's dive into it.

## **Static Analysis**

When opening the binary in a disassembler like IDA, the heavy MOV obfuscation becomes immediately apparent. The code consists of massive blocks of `MOV` instructions with lookup tables embedded in the binary data sections.

### **Decompiling a MOV-Obfuscated binary**
The heavy MOV obfuscation, in addition to stripping the binary makes productive static analysis all but useless, as we can see here some example of disassembly in IDA:
```
.text:0804907C start:                                  ; DATA XREF: LOAD:08048018↑o
.text:0804907C                 mov     dword_8401280, esp
.text:08049082                 mov     esp, off_8401270
.text:08049088                 mov     esp, [esp-200068h]
.text:0804908F                 mov     esp, [esp-200068h]
.text:08049096                 mov     esp, [esp-200068h]
```

Trying to decompile it is even worse, I couldn't even do it in IDA in an easy way, so I won't note it here.

### **Why not try `demovfuscator` ?**

Well of course I tried using it. After an hour or 2 trying to build it & use it effectively, I finally demovfuscated the movfuscated binary (lots of complicated words).

I noticed that after demovfuscation, the binary now crashes with [SIGSEGV](https://en.wikipedia.org/wiki/Segmentation_fault), even with normal input.

At that point, I was 3-4 hours into the challenge, I haven't pwned any other challenge before it, so I was starting to get impatient, I decided to just bruteforce my way by dynamically analyzing the original, obfuscated binary.

## **Dynamic Analysis**

Now that we are sure we can't look our way in the code to the flag, we for sure need to analyze its behavior to understand what it's exactly doing, one of the best disassemblers I use mainly for pwning & reverse engineering is [pwndbg](https://pwndbg.re/stable/), which is an extension of the famous, industry standard debugger, [GNU Debugger (or GDB)](https://sourceware.org/gdb/).

### **Key Observations from Dynamic Analysis**

I spent like 20 minutes going through pure assembly instructions and trying to catch any patterns, fortunately, there was some sense in such a heavily obfuscated code:

1. **Static Length Check**: The binary checks for something against the value `0x49`, which happens to be the expected length of the flag
   - it exits abruptly if the length isn't met

2. **Repeated Patterns**: The binary contains repeating patterns where:
   - A constant byte value is loaded
   - A series of `MOV` instructions operate on it
   - The result is compared with an expected value
   - This pattern repeats 6 times

3. **Stage 01 Recognition**: The first six blocks correspond to validating the prefix "HACKDAY{":
   - Each block validates one character of the prefix
   - The characters are: 'H', 'A', 'C', 'K', 'D', 'A', 'Y', '{'
   - The implementation uses straightforward table lookups for these simple byte comparisons

4. **Stage 02 Obfuscation**: After the prefix validation, the obfuscation becomes more complex:
   - The naive table-based approach is abandoned
   - The binary uses more sophisticated techniques to validate the remaining input
   - Direct analysis of `MOV` instructions becomes impractical, Not gonna lie I stopped using GDB here

## **Stage 01: Prefix Validation**

### **Strategy**

The first stage validates that the input starts with "HACKDAY{". Since the obfuscation for this stage is relatively straightforward, we can:
1. Use a disassembler to identify the 6 blocks
2. Trace through each block to understand the expected character
3. Identify the comparison logic

### **Implementation**

Each block follows this general pattern of a lot of obfuscated assignments, what interests us the most is the static characters loaded by value, e.g.
```
0x804ca58    mov    dword ptr [0x8058188], 0x48     [0x8058188] <= 0x48 'H'
0x804d479    mov    dword ptr [0x8058188], 0x41     [0x8058188] <= 0x41 'A'
0x804de9a    mov    dword ptr [0x8058188], 0x43     [0x8058188] <= 0x43 'C'
0x804e8bb    mov    dword ptr [0x8058188], 0x4b     [0x8058188] <= 0x4b 'K'
...
```

By manually tracing these patterns or using a script (they are generally ~`0xa21` bytes apart), we can extract that the first 6 characters must be "HACKDAY{".

### **Validation**

Testing with input starting with "HACKDAY{" passes the first stage. Any deviation causes the binary to terminate with failure.

## **Stage 02: Hash Validation and Bruteforcing**

### **Why We Didn't Continue with Stage 01's Approach**

Once we pass the "HACKDAY{" prefix, the obfuscation strategy changes dramatically:
- The simple table-lookup patterns disappear
- New, more complex obfuscation layers take over
- Dynamic Analysis by debugger isn't that efficient anymore

### **Pivoting to `ltrace` Dynamic Analysis**

The key insight is to use **dynamic behavior analysis** with `ltrace` to observe the program's runtime library calls.

### **Key Discovery: Input Length Validation**

If the input length is not exactly `0x49` bytes (73 in decimal), the program terminates without reaching the validation logic. This makes sense because:
- Flag format: `HACKDAY{` (8 characters) + SHA256 hash (64 hex characters) + `}` (1 character) = 73 bytes total

Output with incorrect length:
```sh
$ ltrace ./your_mov "HACKDAY{aad56c9ee9ee499f369580746731c1cc7048b5f86cc44ffc4ae63a03f8169f1"
sigaction(SIGSEGV, {0x8049070, <>, 0, nil}, nil)                      = 0
sigaction(SIGILL, {0x80490f7, <>, 0, nil}, nil)                       = 0
--- SIGSEGV (Segmentation fault) ---
strlen("HACKDAY{aad56c9ee9ee499f36958074"...)                         = 71
--- SIGILL (Illegal instruction) ---
--- SIGSEGV (Segmentation fault) ---
exit(2 <no return ...>
+++ exited (status 2) +++
```

### **Identifying the Validation Method**

With a correctly formatted input (`HACKDAY{` + 64 hex digits + `}`), `ltrace` reveals that the binary was using `memcpy` under the hood:
```sh
$ ltrace ./your_mov "HACKDAY{aad56c9ee9ee499f369580746731c1cc7048b5f86cc44ffc4ae63a03f8169f11}"
sigaction(SIGSEGV, {0x8049070, <>, 0, nil}, nil)                    = 0
sigaction(SIGILL, {0x80490f7, <>, 0, nil}, nil)                     = 0
--- SIGSEGV (Segmentation fault) ---
strlen("HACKDAY{aad56c9ee9ee499f36958074"...)                       = 73
--- SIGSEGV (Segmentation fault) ---
memcpy(0x8601270, "H", 1)                                           = 0x8601270
--- SIGSEGV (Segmentation fault) ---
memcpy(0x8601270, "HA", 2)                                          = 0x8601270
...
--- SIGSEGV (Segmentation fault) ---
memcpy(0x8601270, "HACKDAY", 7)                                     = 0x8601270
--- SIGILL (Illegal instruction) ---
--- SIGILL (Illegal instruction) ---
--- SIGSEGV (Segmentation fault) ---
exit(2 <no return ...>
+++ exited (status 2) +++
```

Each incorrect byte results in fewer `memcmp` calls before failure. Each correct byte allows more `memcmp` calls to proceed.

### **Bruteforcing the Hash**

We can exploit this behavior pattern using the following strategy:

1. **Start with static prefix**: `HACKDAY{`
2. **Use placeholder suffix**: Fill remaining 64 bytes with known characters (e.g., "aabaaac...")
3. **Iterate through each position** (0 to 63):
   - Try all possible byte values (0x00 to 0xFF)
   - Count the number of `memcmp` calls in the `ltrace` output
   - The byte that generates the **most `memcmp` calls** is the correct one
4. **Update prefix** and **shrink suffix** for the next iteration
5. **Repeat** until all 64 bytes are found

## **Solve Script**
You can find the full solve script [here](./exploit.py).

<u>**Note:**</u> It can be optimized to use parralel computing & multi-threading, but I didn't find it necessary, as it currently gets the full flag in ~2 minutes.

### **How It Works**

1. **Initial Setup**: Start with the known prefix "HACKDAY{" and a placeholder suffix
2. **Inner Loop**: For each byte position, try all possible values (0x00-0xFF)
3. **Run and Count**: Execute the binary with `ltrace` and count `memcmp` calls
4. **Track Maximum**: Remember the byte value that produced the most `memcmp` calls
5. **Update**: Prepend the correct byte to PREFIX and remove it from SUFFIX
6. **Iterate**: Repeat for the next byte position until all 64 bytes are discovered

The algorithm effectively reduces the bruteforce complexity from $2^{512}$ (trying all possible SHA256 hashes) to $256 \times 64 = 16,384$ operations (trying each byte value at each of 64 positions).

## **Proof of Concept**

```sh
$ ./exploit.py

-- TURN 0x00 --
max_cmps_id: 7e
current prefix: HACKDAY{7e

-- TURN 0x02 --
max_cmps_id: d5
current prefix: HACKDAY{7ed5

...

-- TURN 0x3e --
max_cmps_id: 11
current prefix: HACKDAY{7ed56c9ee9ee499f369580746731c1cc7048b5f86cc44ffc4ae63a03f8169f11

Flag: HACKDAY{7ed56c9ee9ee499f369580746731c1cc7048b5f86cc44ffc4ae63a03f8169f11}
```

## **Final Notes**

I really liked the challenge, especially that it wasn't GPT-able, at least not directly. It also introduced me to the interesting concept of MOVfuscation, and how MOV is turing complete.

In Summary, great challenge, we don't see such quality often these days, thank you very much, and see you in finals! (if we qualified xD)