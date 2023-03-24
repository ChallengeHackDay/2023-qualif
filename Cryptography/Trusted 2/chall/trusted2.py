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