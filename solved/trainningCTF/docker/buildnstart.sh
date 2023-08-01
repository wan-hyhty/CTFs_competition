#!/bin/sh

sudo apt install -y docker.io
sudo docker build . -t fmtstr8
sudo docker run --rm -p 9998:9998 -it fmtstr8