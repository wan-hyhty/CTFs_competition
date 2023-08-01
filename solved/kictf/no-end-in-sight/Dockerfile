# docker build -t no-end-in-sight . && docker run -p 1337:1337 no-end-in-sight
FROM ubuntu:22.10

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update --fix-missing && apt-get upgrade -y
RUN apt-get install -y make socat

RUN echo "dd0ddeaf2293dd418123b8fb03022337d7ac6ac3  /lib/x86_64-linux-gnu/libc.so.6" | sha1sum -c

RUN adduser --disabled-password --gecos "" user

WORKDIR /home/user/

COPY no-end-in-sight no-end-in-sight
COPY flag.txt flag.txt

EXPOSE 1337
USER user

ENTRYPOINT [ "socat", "-v", "tcp-listen:1337,reuseaddr,fork", "EXEC:'timeout 60 stdbuf -i0 -e0 -o0 ./no-end-in-sight'" ]
