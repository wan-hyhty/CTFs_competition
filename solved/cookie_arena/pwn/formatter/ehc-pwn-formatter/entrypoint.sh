#!/bin/bash

# Secure entrypoint
chmod 600 /entrypoint.sh

cp /flag.txt /home/user/challenge/flag.txt

exec "$@"