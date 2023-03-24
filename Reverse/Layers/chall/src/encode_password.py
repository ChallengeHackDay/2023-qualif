flag = open("../flag.txt", "r").read().strip().removeprefix("HACKDAY{").removesuffix("}")

flag = [ord(c) for c in flag]
flag = [c << 3 for c in flag]
flag = [c ^ 1014125475 for c in flag]

print(flag)