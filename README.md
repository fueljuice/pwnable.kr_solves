# pwnable.kr_solves
writeups/scripts for some of the pwnable.kr challenges i solved

**solution to syscall**

the author informs us that he wrote a new syscall that he manually configured into the kernel. he also provides us with the source code:

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


# crafting the shellcode

the crafting of the shell is the hard part since the system is 32bit ARM and we gotta watch out for the convertion of bytes that represent lowercase letters, and no null bytes.



