# Trusted 2

> Following the leak of an important database in the Sagittarius sector, it has been decided to rework the whole security of the information system. \
> Make sure that the authentication portal is this time secured as it should be.

For this challenge, we have a remote instance running at `sie2op7ohko.hackday.fr:1339`, and the Python script running remotely. \
Here is its content:

```py
#!/usr/bin/env python3

import hashlib
from random import randrange
from ecdsa import NIST256p, ecdsa

G = NIST256p.generator
order = G.order()

priv = randrange(1, order)
pub = G * priv

pub = ecdsa.Public_key(G, pub)
priv = ecdsa.Private_key(pub, priv)

k = randrange(1, 2 ** 127)

banner = """
 _____              _           _    ___    ___   
|_   _|            | |         | |  |__ \  / _ \ 
  | |_ __ _   _ ___| |_ ___  __| |     ) || | | |
  | | '__| | | / __| __/ _ \/ _` |    / / | | | |
  | | |  | |_| \__ \ ||  __/ (_| |   / /_ | |_| |
  \_/_|   \__,_|___/\__\___|\__,_|  |____(_)___/ 
  
"""

print(banner)

welcome = f"Welcome to the magistrates' systems authentication portal. These systems contain confidential information. By authenticating, you accept our terms of usage and confidentiality policy."
welcome_sig = priv.sign(int(hashlib.sha256(welcome.encode()).hexdigest(), 16), k)
challenge = "All the information in this portal is signed so you can verify its authenticity. To authenticate, please send your login and then its signature."
challenge_sig = priv.sign(int(hashlib.sha256(challenge.encode()).hexdigest(), 16), k)

print(welcome)
print((int(welcome_sig.r), int(welcome_sig.s)))
print(challenge)
print((int(challenge_sig.r), int(challenge_sig.s)))

login = input("Login: ")

user_r = input("r: ")
user_s = input("s: ")

try:
    flag_sig = ecdsa.Signature(int(user_r), int(user_s))

except:
    print("This is not a valid signature!")
    exit(1)

if login != "admin":
    print("User not recognized.")
    exit(1)

elif pub.verifies(int(hashlib.sha256(login.encode()).hexdigest(), 16), flag_sig):
    with open("flag.txt", "r") as flag:
        print("Welcome back, magistrate.", flag.read())
else:
    print("The signature does not match.")
```

The challenge basically requires us to log in as `admin` with a valid ECDSA signature, with a private key unknown to us.

If we read about how ECDSA works and what kind of vulnerabilities exist, we can find it pretty quickly: in the script, [the same nonce k is reused](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Security) twice. \
The nonce in ECDSA should always be picked randomly, because with two different signatures using the same nonce, one can compute the private key using known equations.

**Note** : I won't dive into the mathematics behind it here on purpose, because there are already lots of [good articles and resources](https://medium.com/asecuritysite-when-bob-met-alice/not-playing-randomly-the-sony-ps3-and-bitcoin-crypto-hacks-c1fe92bea9bc) online that goes through the it step by step. If you want to learn more about why it is possible and how it works, I highly suggest you to take some time reading those.

Here is my solve script:

```py
from pwn import *
from hashlib import sha256
from ecdsa import ecdsa, NIST256p

p = remote("sie2op7ohko.hackday.fr", 1339)

p.recvlines(9)
line1 = p.recvline().strip()
sig1 = p.recvline().strip()
line2 = p.recvline().strip()
sig2 = p.recvline().strip()

sig1 = ecdsa.Signature(int(sig1[1:-1].split(b", ")[0].decode()), int(sig1[1:-1].split(b", ")[1].decode()))
sig2 = ecdsa.Signature(int(sig2[1:-1].split(b", ")[0].decode()), int(sig2[1:-1].split(b", ")[1].decode()))

h_msg1 = int(sha256(line1).hexdigest(), 16)
h_msg2 = int(sha256(line2).hexdigest(), 16)

G = NIST256p.generator
order = G.order()

# because k has been reused for the two signatures, we can recover it
k = ((h_msg1 - h_msg2) * pow(sig1.s - sig2.s, -1, order)) % order
# and then use k and the signatures to compute the private key
priv = ((sig1.s * k - h_msg1) * pow(sig1.r, -1, order)) % order

pub = ecdsa.Public_key(G, G * priv)
priv = ecdsa.Private_key(pub, priv)

login = "admin"
login_sig = priv.sign(int(hashlib.sha256(login.encode()).hexdigest(), 16), k)

p.recvuntil(b"Login: ")
p.sendline(login.encode())
p.recvuntil(b"r: ")
p.sendline(str(login_sig.r).encode())
p.recvuntil(b"s: ")
p.sendline(str(login_sig.s).encode())

log.success(p.recvline().decode())
```

Result:

```
$ python3 solve.py
[x] Opening connection to sie2op7ohko.hackday.fr on port 1339
[x] Opening connection to sie2op7ohko.hackday.fr on port 1339: Trying ::1
[+] Opening connection to sie2op7ohko.hackday.fr on port 1339: Done
[+] Welcome back, magistrate. HACKDAY{n3v3r_r3u53_n0nc35_1n_3CD54}
[*] Closed connection to sie2op7ohko.hackday.fr port 1339
```

Flag: `HACKDAY{n3v3r_r3u53_n0nc35_1n_3CD54}`