FROM ubuntu:22.04

ADD Bartender /tmp/

## to debug with ida 
# ADD linux_server64 /tmp
# sudo docker run -p 23946:23946 -it [id] 

RUN apt update && apt upgrade -y
RUN apt install python3 python3-pip -y

RUN apt install software-properties-common -y
RUN add-apt-repository -y ppa:linuxuprising/java 
RUN apt install -y default-jre-headless

ENV LD_LIBRARY_PATH=/usr/lib/jvm/default-java/lib/server


