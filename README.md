# pwnable.kr_solves
writeups for some of the pwnable.kr challenges i solved. theres a branch opened for each pwn

# starcraft
simply running the binary we can see its a cli fighting simulator, where we choose a character with certain stats and fight random oppotnets of the same characters.<img width="1779" height="628" alt="image" src="https://github.com/user-attachments/assets/0e2589a7-2f16-453c-b7e9-44b792f6ae04" />
lets dive into ida


<img width="1154" height="500" alt="image" src="https://github.com/user-attachments/assets/97f330b8-efcd-43f8-bad7-175d70f01152" />
looking at main, we can see it calls 2 constructors ive named computer (enemy) and user (player). it then refrences the player's vptr and jumps to the vptr+8 adress. which lands in the unit selection function. this function is a big switch() and return a Unit unit = new XXX(), where xxx can be any type of unit (for example marine). after that theres the game loop (can also so above) which just calls the player and eenmies attack and print statistics from thhier vtables.


<img width="938" height="525" alt="image" src="https://github.com/user-attachments/assets/6fb55e8c-a33c-43b6-86f1-6e516944d0c1" />

after the player win around 10 round he gets the oprutiniy to cheat with a cheat menu which has a BOF with unprotected std::cin read into a buffer. however theres a canary so its practically useless for now<br>

xref `std::cin` unviels 2 more vulns. 1 which is in one of the "ghost" which is again unhelpful due to the canary and the other is a heap BOF that reads 300 characters into a 256 buffer and only acsessible after a certain level in the game. (below)
<img width="956" height="202" alt="image" src="https://github.com/user-attachments/assets/ff8bf9b5-e0cf-4812-a2f2-3b705890ecf3" />
this function is defined in the Unit class as virtual and is inherited into every derived character. that i infer from the static vtable (ro)data (look at Unit_asciiartwork) (this happens since vtables are figured in compile time):
<img width="1048" height="428" alt="image" src="https://github.com/user-attachments/assets/bd34cb1b-5b4c-40c5-85b8-2c88b9c9cd1d" />
unfortunately, this code never get called intentionally.<br> in ordrer to acttualy execute this code we need to use another less visible bug.
<img width="582" height="228" alt="image" src="https://github.com/user-attachments/assets/e62e67d1-4220-47e0-9d8d-f3dd80426eee" />

if we take a look into the `Templar` ctor we see that it has a field (a1+312) that holds a pointer to itself. and in each of the functions in the `Templar`'s uses that pointer to store the stats and call attack instead of the actual pointer. in cpp look something like `this->objPtr->vptr[8]()` instead of  just `this->vptr[8]()`. this is fine by itself, but one of the attack options of templar is morphing into a diffrent character by changing this objPtr into an Arcon() object (see below)
<img width="819" height="314" alt="image" src="https://github.com/user-attachments/assets/6fc90d37-2871-4d36-9764-6e62fb9dcbb8" />
after that, every attack will follow this route:
<img width="786" height="463" alt="image" src="https://github.com/user-attachments/assets/22018040-e25e-48ef-90d9-e70964093789" />
as you can see it will try to call a function from the **objPtr** which points to **Arcon vptr** by that it will try to reach arconVptr[0x00/0x40/0x48/0x50] which if we look at the rodata:
<img width="696" height="275" alt="image" src="https://github.com/user-attachments/assets/018c57a9-293b-4975-ae76-5ac2e97db84b" />
**allows us to jump straight into the heap bof function**
