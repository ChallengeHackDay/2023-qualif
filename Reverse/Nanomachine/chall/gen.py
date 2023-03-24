chars = "WHYW0NTY0UD13?!!"
codes = list(map(ord, chars))
mod = len(codes)

enc = []

for i in range(mod):
    code = codes[i]
    next_code = codes[(i + 1) % mod]
    next_next_code = codes[(i + 2) % mod]

    enc.append(2 * (code ** 2) - 5 * next_code + 3 * next_next_code)

print(enc)