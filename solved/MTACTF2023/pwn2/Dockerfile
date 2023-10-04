FROM pwn.red/jail

COPY --from=ubuntu:20.04 / /srv

ENV JAIL_PORT=5002
ENV JAIL_TIME=3600

COPY chall /srv/app/run
COPY flag.txt /srv/app/flag.txt

RUN chmod 755 /srv/app/run