section .text
    global _start

_start:
    mov rdx, 10
    cmp rdx, 0
    je zero

    ; Nếu nhảy không được thực hiện
    ; Đoạn mã sau đây sẽ được thực hiện
    mov ebx, 1
    mov eax, 1
    int 0x80

zero:
    ; Nếu nhảy được thực hiện
    ; Đoạn mã sau đây sẽ được thực hiện
    mov ebx, 0
    mov eax, 1
    int 0x80