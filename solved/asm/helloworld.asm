section .text
    global _start

_start:
    mov ebx, 0x1
    mov ecx, helloWorld
    mov edx, len_helloWorld
    mov eax, 0x4
    int 0x80

    mov ebx, 0x1
    mov ecx, myNameIsQuang
    mov edx, len_myNameIsQunag
    mov eax, 0x4
    int 0x80

    mov eax, 0x1
    int 0x80

section .data
helloWorld db 'Hello World', 0xa
len_helloWorld equ $ - helloWorld
myNameIsQuang db 'My name is Quang', 0xa
len_myNameIsQunag equ $ - myNameIsQuang