FROM ubuntu:22.04

RUN apt-get update && apt-get install -y socat dash libncurses5 && ln -sf /usr/bin/dash /bin/bash

EXPOSE 1337

RUN addgroup --system ctf && adduser --system --ingroup ctf ctf

RUN chsh -s /bin/bash ctf

COPY challenge/ /home/ctf/

WORKDIR /home/ctf

USER ctf

# Add the following lines to enable cbreak mode
ENV TERM=xterm

CMD ["/usr/bin/socat", "tcp-l:1337,reuseaddr,fork", "EXEC:script -q -c './device_control',pty,stderr,setsid,sigint,sighup,echo=0,sane,raw,ignbrk=1"]