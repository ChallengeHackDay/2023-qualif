# Parrot

## Start the challenge

```
$ sudo docker compose up -d
```

## Deliverables

The file `parrot` in the `bin` folder must be delivered to the players.

## Compilation

```
$ gcc -Wall main.c -o bin/parrot -Wl,-z,relro,-z,now
```