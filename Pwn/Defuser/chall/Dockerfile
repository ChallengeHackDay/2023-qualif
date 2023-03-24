FROM ubuntu:focal

RUN useradd -ms /bin/bash player
RUN echo "player:jwR3ATW9xNStyZ4Cp0V5uxmyzK1UBaaqj6" | chpasswd

WORKDIR /home/player

RUN apt update
RUN apt install -y socat

RUN ln -s /home/player/libc.so ./libc.so.6
RUN ln -s /lib64/ld-linux-x86-64.so.2 ./ld-2.32.so
COPY ./dist/chall_patched ./chall
COPY ./dist/libc.so .
COPY ./dist/ld-2.32.so .
COPY ./flag.txt .

RUN chmod 555 /tmp
RUN chmod -R 555 /home/player
RUN chown player:player ./chall
RUN chmod 444 ./flag.txt

USER player
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/player/chall,stderr"]