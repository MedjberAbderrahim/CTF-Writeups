# **Slab Manager - Pwn Challenge Writeup**

## **Challenge Overview**

* **Category**: Pwn
* **Author**: [Spinel99](https://github.com/MedjberAbderrahim)
* **Synopsis**: This challenge implements a custom "Slab Allocator" on top of the standard heap. The core vulnerability is a classic **Use-After-Free (UAF)** due to a dangling pointer in the slab tracking array.
However, the challenge enforces a strict constraint: `MIN_SLAB_SIZE` is **0x500**. This forces all allocations to bypass Tcache/Fastbins and land directly in Unsorted or Large Bins.
We exploit this to:
1. **Leak Libc & Heap** via Unsorted Bin UAF read.
2. Perform a **Large Bin Attack (LBA)** to overwrite the global `stderr` pointer in `.bss`.
3. Craft a fake `_IO_FILE` structure on the heap and trigger **FSOP** (File Stream Oriented Programming) to execute `system(" sh")`.

## **Environment**

* **Libc Version**:
```sh
$ strings libc.so.6 | grep 'GNU C'
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.12) stable release version 2.35.
```

* **Protections**:
```pwndbg
pwndbg> checksec
Arch:       amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
<div style="page-break-after: always;"></div>

## **Static Analysis**

The binary maintains an array of pointers `slabs[16]` and sizes `sizes[16]`.

### **The Vulnerability**

The bug is located in the `deleteSlab` function:

```c
void deleteSlab(){
...
    if ( slabs[idx] )
    {
      free(slabs[idx]);
      puts("Slab deleted successfully.");
    }
...
}

```

Since `slabs[index]` is not zeroed out, we can still call `readSlab(index)` or `writeSlab(index)` on a freed chunk, a Classic RW-UAF.

### **The Constraint**

The allocator enforces a minimum size:

```c
...
if ( size <= 0x1000 && size > 0x4FF ) {
    _idx = idx;
    slabs[_idx] = malloc(size);
...
```

This means we cannot use Fastbin or Tcache attacks (which operate on chunks < 0x420 bytes). We are forced to play with **Unsorted Bins** and **Large Bins**.

## **Exploitation Strategy**

Since `GOT` is read-only (Full RELRO) and we don't have a stack leak for ROP, we must attack the **GLIBC internal structures**. Our target is `stderr`, a global pointer located in the `.bss` section (easy to target because of No-PIE).

> [!IMPORTANT]
> For those who wonder why specifically picked `stderr@GLIBC_2.2.5` instead of `stdout`/`stdin`, it's because stdout is easy to messup, as we use it right after allocating it, but before writing to it, while stderr's usage is totally controlled by us.

### **Stage 1 — Leaking Libc & Heap**

When a chunk larger than 0x420 is freed, it goes into the **Unsorted Bin**. The `fd` and `bk` pointers of the first chunk in the Unsorted Bin point back to the `main_arena` inside libc.

1. Allocate Slab 0 (0x600).
2. Allocate Slab 1 (Guard chunk to prevent consolidation with top chunk).
3. **Free Slab 0**.
4. **Read Slab 0**: The first 16 bytes contain the `fd` (Libc leak) and `bk` (Heap leak).

### **Stage 2 — Large Bin Attack (LBA)**

We need to write a heap address into `stderr` (stored in `.bss`). Since we can't directly write to arbitrary addresses, we use the **Large Bin Attack**.

In modern glibc (2.30+), there is a check on `bk_nextsize->fd_nextsize`, but we can still perform the attack by overwriting `bk_nextsize`.

You can lookup the detailled technique [here](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/large_bin_attack.c).

Now, `stderr@GLIBC_2.2.5` points to our heap chunk `slabs[3]`.

### **Stage 3 — FSOP (File Stream Oriented Programming)**

We have successfully redirected `stderr` to point to a chunk we control (`slabs[3]`). The program calls `fputs(..., stderr)` whenever we trigger an error (e.g., creating a slab with an invalid index), this is exactly why we didn't choose to overwrite the usual target (`stdout`).

We craft a fake `_IO_FILE` structure inside `slabs[3]`.

**The Payload (House of Apple 2 / Wide Data variant):**

1. **Lock**: Set `_lock` to a writable address (e.g., another heap area) to avoid crashes.
2. **Wide Data**: Set `_wide_data` to point to a controlled area.
3. **Vtable**: Set `vtable` to a particular offset in `_IO_wfile_jumps` Which allows us to call `_IO_wfile_overflow` instead of `_IO_new_file_xsputn`, which calls `_IO_wdoallocbuf`, which in turn calls arbitrary data without vtable checks.
4. **The Hook**: When `fputs` is called on our fake file, it eventually calls `_IO_wfile_overflow`.
5. **Code Execution**: By carefully crafting the internal offsets of the `_wide_data` structure, we can trick `_IO_wfile_overflow` into calling `system(" sh")` (or our shell string).

> [!IMPORTANT]
> The space in the ` sh` string is important to bypass some internal check inside `_IO_wfile_overflow`.

To learn about this technique or FSOP in general, You can refer to:
- pwn.college's playlist: [Link](https://www.youtube.com/playlist?list=PL-ymxv0nOtqrD-3LwVyyUu83kNJBI9RVL)
- My Own Notes on FSOP, based on pwn.college's content & my experience: [Link](https://github.com/MedjberAbderrahim/Binary-Exploitation-Notes/tree/main/FSOP) 

#### **Payload Layout (from `exploit.py`)**

```python
fs = flat(
    {
        0x88: p64(libc.sym['_IO_stdfile_2_lock']), # _lock
        0xA0: p64(w_addr),                          # _wide_data
        0xC0: p32(-1, sign="signed"),               # _mode (must be < 0 for wide path)
        0xD8: libc.sym['_IO_wfile_jumps'] ... ,     # vtable pivot
        w_offset+0x68: p64(libc.sym['system'])      # The function to call
    },
    filler=b'\x00'
)

```

Finally, we trigger the chain by sending an invalid menu option or failing a check that calls `fputs(..., stderr)`.

## **Solve Script**

The full solver is provided in [`exploit.py`](./exploit.py).

## **Proof of Concept**

Running the exploit against the local instance:

```sh
$ ./exploit.py REMOTE
[+] Opening connection to localhost on port 10000: Done
libc.address: 0x7f3e0dbfc000
heap_base: 0x121ee000
[*] Switching to interactive mode
flag{L4rg3_514b_t0_th3_w1n!!!}$ 
[*] Interrupted
[*] Closed connection to localhost port 10000
```

## **Final Notes**

Really enjoyed (and suffered) while creating this challenge, always wanted to test out this large bin to FSOP idea but didn't meet it in any CTF lately, well why not give it to y'all xD.

Anyway, hope you'all found this challenge good, either you learnt something new from it, or found it fun & entertaining! see you next time hopefully, meanwhile, happy pwning!