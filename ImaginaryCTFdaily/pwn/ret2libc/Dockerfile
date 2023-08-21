FROM ubuntu:22.04 

RUN useradd -ms /bin/bash pwn
WORKDIR /home/pwn

ADD ret2libc /home/pwn
ADD flag /home/pwn

RUN chmod 004 /home/pwn/flag
RUN chmod 005 /home/pwn/ret2libc

RUN apt-get update -y
RUN apt-get install socat -y
USER pwn

EXPOSE 2007

ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:2007,reuseaddr,fork EXEC:/home/pwn/ret2libc,stderr"]
