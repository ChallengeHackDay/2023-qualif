from pwn import *
from hashlib import sha256

def MAC(msg, key):
    return hashlib.sha256(key + msg).hexdigest()

r = remote("localhost", 1338)

r.recvuntil(b"> ")
example = r.recvline().decode().strip()
r.recvuntil(b"> ")
mac_example = r.recvline().decode().strip()

login = "admin"

secret_size = 32

print("Please open a terminal and run the following command to get the information I need. You'll need to have hash_extender for that (see https://github.com/iagox86/hash_extender).")
print(f"./hash_extender --data '{example}' --secret {secret_size} --append '{login}' --signature {mac_example} --format sha256")

payload = bytes.fromhex(input("New string: "))
mac = input("New signature: ")

r.recvuntil(b"> ")
r.sendline(payload)
r.recvuntil(b"> ")
r.sendline(mac.encode())

log.success(r.clean(0.6).decode())