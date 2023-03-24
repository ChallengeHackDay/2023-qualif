# Defuser

## Start the challenge

```
$ sudo docker compose up -d
```

## Deliverables

The files `chall` and `libc.so` in the `dist` folder must be delivered to the players.

## Compilation

⚠️ You don't need to recompile and most probably shouldn't in order to avoid breaking the challenge. Precompiled binaries are already available in the `dist` folder. \
That being said, if you're curious, you need `gcc` and [`pwninit`](https://github.com/io12/pwninit).

```
$ gcc -Wall chall.c -o dist/chall
$ cd dist
$ pwninit
$ rm solve.py # the auto generated solve stub is not needed
```