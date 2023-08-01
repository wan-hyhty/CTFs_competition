from pwn import *
import socket
import struct

s = socket(AF_INET, SOCK_STREAM)
s.connect(("vortex.labs.overthewire.org"))