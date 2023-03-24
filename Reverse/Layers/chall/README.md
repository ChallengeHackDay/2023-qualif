# Layers

## Compile the project

Use the following commands to compile the project. You need to be on a Linux OS and have [NASM](https://www.nasm.us/) as well as [Rust](https://www.rust-lang.org/) installed.

```
$ cd src
$ nasm -f elf64 shellcode.asm -o shellcode.o
$ ld -m elf_x86_64 shellcode.o -o shellcode # don't worry about the warning given by ld
$ objdump -d shellcode | grep -Po '\s\K[a-f0-9]{2}(?=\s)' | sed 's/^/\\x/g' | perl -pe 's/\r?\n//' | xargs -0 echo -ne > shellcode.bin
$ python3 patch_shellcode.py
$ cargo build --release
```

The executable will be placed in `target/release` with the name `layers`.