FROM ubuntu:focal

RUN apt-get update
RUN apt-get install -y xinetd
RUN apt-get clean
RUN useradd -m Fornback

ADD share/ /home/Fornback/
ADD xinetd /etc/xinetd.d/Fornback

RUN chown -R Fornback:Fornback /home/Fornback
RUN chown root:root /home/Fornback/flag.txt
RUN chown Fornback:root /home/Fornback/fornback
RUN chmod 444 /home/Fornback/flag.txt
RUN chmod +x /home/Fornback/fornback
RUN chmod +x /home/Fornback/libc-2.32.so
RUN chmod +x /home/Fornback/ld-2.32.so
RUN chmod +x /home/Fornback/run.sh

USER Fornback
WORKDIR /home/Fornback

CMD ["/usr/sbin/xinetd", "-dontfork"]