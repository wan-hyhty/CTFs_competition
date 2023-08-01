#!/bin/bash
chal="${CHAL:-ehc-pwn-formatter}"
docker rm -f "$chal"
docker build --tag="$chal" .
docker run -p 1337:1337 --rm --name="${chal}" "${chal}"