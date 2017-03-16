#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BLOCK_SIZE 8

// Using the HelloWorld shellcode
unsigned char original_shellcode[] = 
"\x31\xc0\xb0\x04\x31\xdb\xb3\x01\x31\xd2\x52\x68\x72\x6c\x64\x0a\x68\x6f\x20\x57\x6f\x68\x48\x65\x6c\x6c\x89\xe1\xb2\x0c\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80";

unsigned char key[] = "adam";

// take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3]
void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
} 

int main(void)
{
    int shellcode_size;
    int encrypted_shellcode_size;
    unsigned char * encrypted_shellcode;
    unsigned char * encrypted_shellcode_position;

    // Define size of original and encrypted shellcode
    shellcode_size = sizeof(original_shellcode) - 1;
    encrypted_shellcode_size = ((shellcode_size / BLOCK_SIZE) + 1) * BLOCK_SIZE;

    // Use malloc() to allocate memory for the encrypted shellcode
    encrypted_shellcode = malloc(encrypted_shellcode_size);
    // Check for errors
    if (encrypted_shellcode == NULL)
    {
        printf("Error: malloc() returned NULL pointer.");
        exit(EXIT_FAILURE);
    }

    // Move original shellcode in the memory space allocated to the encrypted shellcode
    memset(encrypted_shellcode, 0, encrypted_shellcode_size);
    memcpy(encrypted_shellcode, original_shellcode, shellcode_size);

    
    encrypted_shellcode_position = encrypted_shellcode;
    while (encrypted_shellcode_position - encrypted_shellcode < encrypted_shellcode_size)
    {
        encipher(32, (uint32_t *)encrypted_shellcode_position, (uint32_t *) key);
        encrypted_shellcode_position += BLOCK_SIZE;
    }

    printf("Original shellcode: ");
    for (int i = 0; i < shellcode_size; i++)
        printf("\\x%02x", original_shellcode[i]);
    printf("\nOriginal shellcode size: %d\n\n", shellcode_size);

    printf("Encrypted shellcode: ");
    for (int i = 0; i < encrypted_shellcode_size; i++)
        printf("\\x%02x", encrypted_shellcode[i]);
    printf("\nEncrypted shellcode size: %d\n\n", encrypted_shellcode_size);

    free(encrypted_shellcode);

    return 0;
}
