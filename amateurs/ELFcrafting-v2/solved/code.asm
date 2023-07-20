BITS 32
ORG 0x10000
DEFAULT ABS

; https://wiki.osdev.org/ELF
; https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
elfheader:
    db 0x7F, "ELF"
    ;db 1 ; 32 bit
    ;db 1 ; LE
    ;db 1 ; EI_VERSION
    ;db 0 ; SYSV
    dd 0x01 ; p_type LOAD
    dd 0 ; p_offset
    dd $$ ; p_vaddr
    ;db 0 ; abi ver, unused
    ;db 0, 0, 0, 0, 0, 0, 0 ; unused
    dw 0x02 ; exec
    dw 0x03 ; x86
    ;dd 0x10000 ; p_paddr
    ;dd 1 ; elf ver, unused
    dd entry ; p_filesz
    dd entry
    ;dd end-elfheader ; p_memsz
    ;dd phtable - elfheader ; phoff
    dd 0x4 ; p_flags RWX
    dd 0x10000 ; p_align, any val
;    dd 0 ; shoff, unused
    dd 0 ; flags unused
    dw 0x34
    dw 0x20 ; phentsize
    dw 1 ; phnum
;    dw 40 ; shentsize
;    dw 0 ; shnum
;    dw 0 ; shstrndx, unused

entry:
    ;mov [end_filepath], al
    ;mov [end_execname], al
    ;.execve:
    ;mov al, 0xB
    ;mov ebx, execname
    ;mov ecx, argv
    ;; edx == 0
    ;int 0x80

    .mmap:
    ; mov al, 0x5A
    mov al, 0xC0
    ; ebx is zero
    mov cx, 0x1000
    mov dl, 1 | 2 | 4
    mov si, 0x20 | 0x02
    mov di, -1
    ; ebp is zero
    int 0x80

    .read:
    mov ecx, eax
    xor eax, eax
    mov al, 3
    mov dl, 0xff
    ; inc bl
    int 0x80

    .jmp:
    jmp ecx

;    .exit:
;	mov	ebx,0
;	mov	eax,1
;	int	0x80

;filepath: db "flag.txt", 0 ; 9 bytes
;execname: db "/bin/cat", 0 ; 9 bytes
;argv: dd execname, filepath, 0 ; 12 bytes

;times 79 - ($ - $$) db 0

end:
