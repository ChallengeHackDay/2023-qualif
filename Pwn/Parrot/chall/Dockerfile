FROM ubuntu:focal

RUN useradd -ms /bin/bash player
RUN echo "player:1cNSX6D7YtEdsn5wJnDDzcmQYGVQ4hPJR3" | chpasswd

WORKDIR /home/player

RUN apt update
RUN apt install -y socat

RUN chmod 555 /tmp

COPY ./bin/parrot .
COPY ./flag.txt .

RUN chmod -R 555 /home/player
RUN chown player:player ./parrot
RUN chmod 444 ./flag.txt

USER player
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/player/parrot,stderr"]