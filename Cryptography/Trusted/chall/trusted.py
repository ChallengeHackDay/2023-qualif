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