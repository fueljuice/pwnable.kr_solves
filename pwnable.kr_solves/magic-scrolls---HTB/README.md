# pwnable.kr_solves
writeups for some of the pwnable.kr challenges i solved. theres a branch opened for each pwn

prootf of solve: https://labs.hackthebox.com/achievement/challenge/3986433/634

this challenge is starts as a menu that lets you create "spells" which are heap objects. creating them with malloc with a create spell function
<img width="375" height="171" alt="image" src="https://github.com/user-attachments/assets/c3efe6bb-c23a-4f70-b8f2-a5149ec094cf" />

and destroying them by index with remove_spell

<img width="282" height="224" alt="image" src="https://github.com/user-attachments/assets/3b1dc477-3a30-42c1-ba7c-88c21ef36e4e" />

you can also set a spell as favorite which allows you to read its contents. this choice is permanent. you cannot read after free bceause it sets the ptr to null and the cached length as 0 so the read function does nothing<br>

additionaly theres a function which contains a vulnrability(update_magic_numbers):

<img width="434" height="470" alt="image" src="https://github.com/user-attachments/assets/016e4f99-5f4b-46cf-89ba-e198a4747258" />

you can overwrite the lowest byte of the first 2 chunks allocated, or ovewrite them entirely:

<img width="492" height="451" alt="image" src="https://github.com/user-attachments/assets/5001157b-db4b-4e71-b611-56839045506c" />

since PIE is on we cannot guess a pointer to overwrite so its for now useless. but, since we can overwrite both of the first chunks highest byte as 0 we can make them point to the same adress. for exmaple if they were 0x123345 and 0x123356. theyre now both 0x123300. this lets us do this exploit: <br>
1. create_spell with chunk 0 and 1 and writing 255bytes into 1 (maximum).
2. free chunk 0
3. corrupt thier last byte with the update_magic_numbers
4. set chunk1 to favorite and read. the read will read from the 0x123300 to 0x123345 and more which contains the tcache's pointer which **points to the heap base**<br>

now that we basically have arbitrary write, but since theres pie we can only read from the heap. we can also exploit a house of spirit with these vulns, but we dont have a target. so well set the target to the stack. leaking the stack with libc base follows this route: leak smallbin/unsortedbin pointers, calculate libc base from pointer leak environ, profit (:< <br>
so i made 7 tcaches size 200 bytes (bigger than fastbin, cuz doesnt point to libc), forced a unsortedbin, rewrote chunk 1 pointer as &unsortedbin (by offset) and leaked the pointer with read functiom.<br> similarliy with the environ, just calculate environ from libc and read. <br> 

now i set the target on the return adress of the create_spell which is a constant distance from environ. in order to do that ill help to exploit a house of spirit: <br>
1.  create and free a 48 bytes spell. (will make sence later, to increase the libc count variable in the 48 tcache bin)
3.  create a new chunk size 255 and heap spray it with p64(0x0) + p64(0x40) (prev size + chunk size) to make fake chunks headers.
4.  shift the chunk1 pointer with the vuln into the heap spray and use the remove spell fnction to call free on the fake header and make a 48 byte tcache inside the chunk
5.  free the heap spray chunk
6.  remake the heap spray chunk but instead of spraying it again poison the tcache inside it with the adress of the return adress in the stack of create_spell.
7.  make 2 chunks size 48 bytes. and in the second create a system binsh ropchain
**PROFIT !!!**
