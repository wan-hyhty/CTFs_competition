FROM ubuntu:22.04 

RUN useradd -ms /bin/bash pwn
WORKDIR /home/pwn

ADD ret3libc /home/pwn
ADD flag /home/pwn

RUN chmod 4 /home/pwn/flag
RUN chmod 5 /home/pwn/ret3libc

RUN apt-get update -y
RUN apt-get install socat -y
USER pwn

EXPOSE 2007

ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:2007,reuseaddr,fork EXEC:/home/pwn/ret3libc,stderr"]
