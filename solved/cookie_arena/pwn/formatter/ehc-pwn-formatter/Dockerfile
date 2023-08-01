FROM ubuntu:22.04

RUN apt-get update && apt-get install -y supervisor socat && apt-get clean

RUN useradd -md /home/user user

WORKDIR /home/user/challenge

COPY challenge /home/user/challenge
COPY config/supervisord.conf /etc/supervisord.conf

# Copy flag
COPY flag.txt /flag.txt

# Setup permissions
RUN chown -R user:user /home/user/challenge /flag.txt
RUN chmod 755 /home/user/challenge
RUN chmod a+x /home/user/challenge/source

# Expose the port nginx is listening on
EXPOSE 1337

# Generate random flag filename and start supervisord
COPY --chown=root entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]