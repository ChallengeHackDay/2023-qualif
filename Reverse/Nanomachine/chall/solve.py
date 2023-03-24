from z3 import *

enc = [15045, 10184, 15551, 15132, 4470, 12015, 13811, 15857, 4387, 14257, 9156, 4736, 4986, 7872, 2274, 1959]
mod = len(enc)

s = Solver()

chars = [Real(f"c{i}") for i in range(0, mod)]

for i in range(mod):
    code = chars[i]
    next_code = chars[(i + 1) % mod]
    next_next_code = chars[(i + 2) % mod]

    s.add(2 * (code ** 2) - 5 * next_code + 3 * next_next_code == enc[i])
    

if s.check() == sat:
    model = s.model()
    serial = "".join(map(chr, [model[c].as_long() for c in chars]))
    flag = "HACKDAY{" + "-".join([serial[i:i+4] for i in range(0, len(serial), 4)]) + "}"
    print(flag)