section .text:
    global _start
section .bss
    num_a resb 5
    num_b resb 5
    num_tong resb 5

_start:
    mov ebx, 0x1
    mov ecx, msg
    mov edx, len_nhapVao
    mov eax, 0x4
    int 0x80

    mov eax, 0x3
    mov ebx, 0x2
    mov ecx, num_a
    mov edx, 5
    int 80

    mov eax, 0x3
    mov ebx, 0x2
    mov ecx, num_b
    mov edx, 5
    int 80

    xor eax, eax
    mov eax, num_a
    add eax, num_b
    mov num_a,eax

    mov eax 0x4
    mov ebx, 0x1
    mov ecx, num_tong
    mov edx, 5
    int 0x80

    mov eax, 0x1
    int 0x80

section .data:
msg db "Nhap vao 2 so a va b: "
len_nhapVao equ $ - msg
msg_tong db "Tong: "
len_tong equ $ - msg_tong
msg_hieu db "Hieu: "
len_hieu equ $ - msg_hieu
