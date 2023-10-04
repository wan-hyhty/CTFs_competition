#!/bin/sh

# Local and Public
gcc r.c -o fornback
patchelf --set-interpreter ./ld-2.32.so fornback
patchelf --replace-needed libc.so.6 ./libc-2.32.so fornback