#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BLOCK_SIZE 8

// Encrypted HelloWorld shellcode
unsigned char encrypted_shellcode[] = 
"\x55\x87\xf9\x52\x4e\xcf\x91\xa4\x66\x71\xb2\x20\xab\x56\x9d\x57\x4d\x56\x74\x42\xa0\x90\x3b\x35\x0e\x04\x1d\x4c\x7f\xb2\xbb\x08\x90\xf2\x81\x8d\x4a\x83\x09\x76\xc2\xe6\x6d\xb3\x54\xf7\x8b\x74";

unsigned char key[] = "adam";

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

int main(void)
{
    int encrypted_shellcode_size;
    unsigned char * encrypted_shellcode_position;

    // Define size of encrypted shellcode
    encrypted_shellcode_size = sizeof(encrypted_shellcode) - 1;

    // Print encrypted shellcode
    printf("Encrypted shellcode: ");
    for (int i = 0; i < encrypted_shellcode_size; i++)
        printf("/x%02x", encrypted_shellcode[i]);
    printf("\nEncrypted shellcode size: %d\n\n", encrypted_shellcode_size);

    // Decrypt encrypted shellcode
    encrypted_shellcode_position = encrypted_shellcode;
    while (encrypted_shellcode_position - encrypted_shellcode < encrypted_shellcode_size)
    {
        decipher(32, (uint32_t *)encrypted_shellcode_position, (uint32_t *) key);
        encrypted_shellcode_position += BLOCK_SIZE;
    }

    // Print original shellcode
    printf("Original shellcode: ");
    for (int i = 0; i < encrypted_shellcode_size; i++)
        printf("/x%02x", encrypted_shellcode[i]);
    printf("\n\n");

    // Execute original shellcode 
    int (*ret)() = (int(*)()) encrypted_shellcode;
    ret();

    return 0;
}


