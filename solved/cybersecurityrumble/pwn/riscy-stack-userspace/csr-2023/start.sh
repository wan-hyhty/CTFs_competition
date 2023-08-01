#!/bin/sh

timeout 5m qemu-system-riscv64 \
    -M virt \
    -m 128M \
    -no-reboot \
    -monitor none \
    -nographic \
    -bios firmware.bin \
    -kernel kernel.bin
