# Trusted

> The situation is bad. The magistrate database from the Sagittarius sector has been leaked! \
> The incident response team continues to see unknown connections in the logs from outside the sector, even though the passwords have all been changed. \
> We suspect the problem is with the authentication portal... Do something about it!

For this challenge, we have a remote instance running at `sie2op7ohko.hackday.fr:1338`, and the Python script running remotely. \
Here is its content:

```py
#!/usr/bin/env python3

import hashlib
from random import randbytes

def MAC(msg, key):
    return hashlib.sha256(key + msg).hexdigest()

secret = randbytes(32)

example = "my_login"
mac_example = MAC(example.encode(), secret)

banner = f"""
 _____              _           _ 
|_   _|            | |         | |
  | |_ __ _   _ ___| |_ ___  __| |
  | | '__| | | / __| __/ _ \/ _` |
  | | |  | |_| \__ \ ||  __/ (_| |
  \_/_|   \__,_|___/\__\___|\__,_|

Welcome to the magistrates' systems authentication portal.
These systems contain confidential information. By authenticating, you accept our terms of usage and confidentiality policy.
On a first line, please send your login. On a second line, send the MAC of the login.

Here's an example:

> {example}
> {mac_example}

"""

print(banner)

login = input("> ").encode("utf-8", "surrogateescape")
mac = input("> ")

if b"admin" not in login:
    print("User not recognized.")
    exit(1)

if mac != MAC(login, secret):
    print("Login error, the MAC is invalid.")
    exit(1)

with open("flag.txt") as flag:
    print("Welcome, dear magistrate.", flag.read())
```

This challenge is white box, we have to reach the part that will read and print the flag. It is supposed to be protected by a kind of MAC based on a random 32 bytes secret.

If we search a bit online about MAC in general, we see that HMAC is the most used today and it is more complicated than just `hash(secret || message)` as is the case in the program. If we search more information about that, we can see that using this naive formula is [vulnerable]((https://en.wikipedia.org/wiki/HMAC#Design_principles)) to the [length-extension attack](https://en.wikipedia.org/wiki/Length_extension_attack) for certain hash functions, including SHA2, which is the one used here.

Basically, the concept is that knowing an existing value and its MAC, we can initialize the internal state of the hash function with the existing hash, and then continue the hash computation with the data we want. \
It means that knowing `hash(secret || data)`, we can compute `hash(secret || data || attacker_controlled_data)`.

For that, I chose to use the existing tool [Hash Extender](https://github.com/iagox86/hash_extender) to simplify the process and wrote my solve script around it.

```py
from pwn import *
from hashlib import sha256

def MAC(msg, key):
    return hashlib.sha256(key + msg).hexdigest()

r = remote("sie2op7ohko.hackday.fr", 1338)

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
```

**Note** : [hlextend](https://github.com/stephenbradshaw/hlextend) also works and allow you to use pure Python only instead of using an external tool like I did.

Result:

```
$ python3 solve.py
[x] Opening connection to sie2op7ohko.hackday.fr on port 1338
[x] Opening connection to sie2op7ohko.hackday.fr on port 1338: Trying ::1
[+] Opening connection to sie2op7ohko.hackday.fr on port 1338: Done
Please open a terminal and run the following command to get the information I need. You'll need to have hash_extender for that (see https://github.com/iagox86/hash_extender).
./hash_extender --data 'my_login' --secret 32 --append 'admin' --signature 75487b93df33639ddcb690068d09a1b971d018fbf0dd79067872c55724325708 --format sha256
New string: 6d795f6c6f67696e80000000000000000000000000000000000000000000014061646d696e
New signature: d4f1969e94422acbf1f6c5ff64e31e1756a38ae103407336b0f6a3ac958d3d04
[+] Welcome, dear magistrate. HACKDAY{l3ngth_3xt3n510n_4tt4ck5}
[*] Closed connection to sie2op7ohko.hackday.fr port 1338
```

Flag: `HACKDAY{l3ngth_3xt3n510n_4tt4ck5}`