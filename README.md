# pwnable.kr_solves
writeups/scripts for some of the pwnable.kr challenges i solved

**this challenge requires syscall's flag, because it is a more advanced exploitation of a kernel vulnrabillities**

ive searched on google the name of the challenge `exynos`, and i found that it is a samsung cpu. it matched the description of the challenge: `How did Samsung accidently mess up their phone?`. 

the system provides us with root directory with one new executable, that the normal linux kernel doesnt contain: `exynos-mem`. as i turns out theres an CVE for that, called CVE-2012-6422. the author of the CVE claims it lets the any user to get acsess to all physical memory of the kernel. it is like /dev/mem, but unlike /dev/mem/, it has no restrictions and doesnt require root😵. the only "security" check is forbidding us to step out of the kernel adrsses (which doesnt bother us whatsoever) :



<img width="561" height="146" alt="Screenshot_147" src="https://github.com/user-attachments/assets/8944e093-2503-407f-93de-bb879a97c146" />

in contrast to the original `exynos-mem (/dev/exynos-mem)`, which is a charcater device (a special handle into a kernel driver that lets you talk to memory-mapping functions.), this ctf version of the the file is an executable with root privilege. 

<img width="567" height="41" alt="Screenshot_148" src="https://github.com/user-attachments/assets/9539a665-d618-4b82-b297-f9479345f2b3" />


it also asks for arguments:

<img width="452" height="37" alt="Screenshot_149" src="https://github.com/user-attachments/assets/98853d06-fc9c-4876-8b68-ec2a637c3bfa" />

the physical argv[1]: adress we want to map. argv[2]: how many bytes to map. argv[3]: r/w mode. from the arguemnts we can understand it only dumps bytes and can leak kernel adresses and can NOT patch or change them. in the original exploit the author leaked the adress of setuserid and patched its code so theres no root requirment. now the hard part of this pwn is to figure out how to get a priviliage escalation solely from leaking memory.

# exploit
 we need to dump the entire physical memory,so lets check where it is located with `cat /proc/iomem`
 
 <img width="298" height="43" alt="Screenshot_150" src="https://github.com/user-attachments/assets/7bf6735b-3da7-45cf-8770-2ba482cc9958" />

weve got the first parameter to pass to exynos-mem: PHYSICAL_ADRESS = 0x60000000

for the bytesize, ill copy the original exploit's code and use
```c
     int page_size = sysconf(_SC_PAGE_SIZE);
     int length = page_size * page_size;
```
