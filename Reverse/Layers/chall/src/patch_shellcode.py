with open("shellcode.bin", "r+b") as f:
    shellcode = f.read()
    patched = b""
    for b in shellcode:
        patched += bytes([b ^ 137])
    f.seek(0)
    f.write(patched)