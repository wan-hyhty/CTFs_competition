#!/bin/sh

cd /home/user
socat tcp-listen:9998,fork,reuseaddr exec:./fmtstr8 2>/dev/null