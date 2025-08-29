# pwnable.kr_solves
writeups/scripts for some of the pwnable.kr challenges i solved
**this one will not be as elaborate as usual**

for some context we get an executable rsa_calculator that encrypts/decrypts rsa asymetric encyprtion with keys with provide. it consists of a menu with options: set key, encrypt decrypt exit and help. these are poorly managed by an array of functions on the bss.

i opened the executable on ida. and in the second, encrypt option theres an overflowable bufffer that stores the encrypted data g_ebuf:
<img width="1279" height="654" alt="Screenshot_152" src="https://github.com/user-attachments/assets/c5d7299d-85f6-42f9-bd9f-19fdfb44be5a" />

g_ebuf is only 256 bytes in the bss. and it can be overflown to 1024 bytes. the g_ebuf is on a lower in memory than the function array so we potentially mess with it. 

# hard part
if we could directly put our input into the g_ebuf we could insert a shellcode into it and overflow it to the menu so we will jump striaght to the shell code **however**, the g_ebuf buffer is the rsa encrypted version of our data, and this implementation is very bad and consist alot of mistakes.

 
