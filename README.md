# pwnable.kr_solves
writeups/scripts for some of the pwnable.kr challenges i solved

**solution to syscall**

the author informs us that he wrote a new syscall that he manually configured into the kernel syscall table. he also provides the source code:

```c
// adding a new system call : sys_upper

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <linux/syscalls.h>

#define SYS_CALL_TABLE		0x8000e348		// manually configure this address!!
#define NR_SYS_UNUSED		223

//Pointers to re-mapped writable pages
unsigned int** sct;

asmlinkage long sys_upper(char *in, char* out){
	int len = strlen(in);
	int i;
	for(i=0; i<len; i++){
		if(in[i]>=0x61 && in[i]<=0x7a){
			out[i] = in[i] - 0x20;
		}
		else{
			out[i] = in[i];
		}
	}
	return 0;
}

static int __init initmodule(void ){
	sct = (unsigned int**)SYS_CALL_TABLE;
	sct[NR_SYS_UNUSED] = sys_upper;
	printk("sys_upper(number : 223) is added\n");
	return 0;
}

static void __exit exitmodule(void ){
	return;
}

module_init( initmodule );
module_exit( exitmodule );
```
# vulnrabillity
ive read about kernel exploits and it helped me understand the vulnrabillity in this syscall: since the function doesnt check whether the parameters come from userspace or kernel space using functions such as
<img width="1560" height="287" alt="Screenshot_137" src="https://github.com/user-attachments/assets/8731f3d2-7132-4ad1-a454-c4fc2fcec168" />

we can overwrite other syscalls with commit_creds() and prepare_kernel_cred(0) functions. we will perform it using the line `out[i] = in[i]` that lets us overwrite everything in the second parameter with the first. we can open /proc/kallsyms file, that stores all the kernel symbols together with the grep command.




<img width="397" height="149" alt="Screenshot_139" src="https://github.com/user-attachments/assets/fe0acc2e-53c7-4476-b144-9e0a387ecbde" />


# shellcode

the idea is to enter the adress of the privelage escalation functions into random syscalls on the system_calll_table. however, theres a problem, because the location of commit_creds contains a byte that is contains a byte that also represents a lowercase letter (`0x6c`), which means the program will change it to something else. to avoid that, ill change the value of the byte so it wont be in the conversion range between 0x61-0x7a (`if(in[i]>=0x61 && in[i]<=0x7a){out[i] = in[i] - 0x20;}`) 
quick math:

**0x6c- 0x61 - 1 = 0xc = 12** 

so we need to subtract 12 from the adresss of commit_creds: **0x8003f56c - 12 = 0x8003f560**. last thing we need to handle is filling the gap between 0x8003f56c and 0x8003f560 with nops (because we dont want random code to raise a segfault) the arch of the cpu is arm (ew):



<img width="453" height="37" alt="Screenshot_141" src="https://github.com/user-attachments/assets/974aff08-6db8-48e5-a585-90f27b32d5a8" />

ive searched online and found that nop in arm can be simply be done with moving a register into itself, for example mov r0,r0 (btw this example is not valid since it contains null bytes in hexa that will fk up the syscall)


<img width="1407" height="557" alt="Screenshot_143" src="https://github.com/user-attachments/assets/146ad540-0077-4044-9703-af443527426d" />

heres the hexa version of it. we need 12 bytes so we will multiply it three times: "\x01\x10\xa0\xe1\x01\x10\xa0\xe1\x01\x10\xa0\xe1"
