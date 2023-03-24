from pwn import *
from hashlib import sha256
from ecdsa import ecdsa, NIST256p

p = remote("localhost", 1337)

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

# the nonce k is constant for every signature, where it should have been randomized each time
# because of this, we can deduce the value of k used for both signatures and then compute the private key from it
# for more info, see https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Security
k = ((h_msg1 - h_msg2) * pow(sig1.s - sig2.s, -1, order)) % order
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