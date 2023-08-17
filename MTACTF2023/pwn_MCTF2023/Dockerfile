FROM ubuntu:20.04

MAINTAINER setant
RUN apt-get update
RUN apt-get install fping -y

RUN useradd -m chall 

COPY ./share/flag /flag
COPY ./share/run.sh /home/chall/run.sh
COPY ./share/chall /home/chall/chall

RUN chmod +x /home/chall/run.sh

RUN chown -R root:chall /home/chall
RUN chmod -R 755 /home/chall
RUN chmod 644 /flag

RUN echo chall > /etc/cron.deny
RUN chmod 644 /etc/cron.deny

RUN chmod -R 774 /var/tmp
RUN chmod -R 774 /tmp
RUN chmod -R 774 /dev
RUN chmod -R 774 /run
RUN chmod 1733 /dev/shm
USER chall

WORKDIR /home/chall
 
CMD ["./chall"]

EXPOSE 1337
