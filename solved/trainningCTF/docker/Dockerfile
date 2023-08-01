FROM ubuntu:20.04

RUN apt update && \
	apt install -y socat && \
	apt clean && \
	useradd -m user

ADD share/ /home/user/

WORKDIR /home/user
RUN chmod 444 flag.txt && \
	chmod +x fmtstr8 run.sh

USER user
CMD ["/home/user/run.sh"]