# pwnable.kr_solves
writeups/scripts for some of the pwnable.kr challenges i solved

**sol7.py conatins the writeup solution for dragon**

the machine contains an executable with a game. the game has 2 modes. a gampley that is traditionally unwinable, and a secret level.

the secret levels gives us a shell if we input the correct password:

<img width="675" height="390" alt="Screenshot_154" src="https://github.com/user-attachments/assets/6bff857c-daf8-49de-a625-b2cfadb04487" />


however, as you can see, the code only allocates us 10 bytes to input and the password is longer than that, meaning we cant get the pasword right no matter what.

the game:


<img width="439" height="667" alt="Screenshot_155" src="https://github.com/user-attachments/assets/838257f5-48c3-4cbe-a0b0-26491ef47abc" />
<img width="527" height="698" alt="Screenshot_156" src="https://github.com/user-attachments/assets/cbca6b35-6b87-429f-a301-0f9f9839cf95" />


allocates 2 arrays. one is a player array and the other is the monster array. however, for some reason, the monster health is stored in a single byte:

<img width="305" height="142" alt="Screenshot_157" src="https://github.com/user-attachments/assets/244c584b-67e2-4f6a-9507-a73b279c9b16" />

the game lets us choose 2 characters, priest and knight. if we choose priest, we have an option of holy bolt that deals damage, clarity that gives us mana and holyshield that makes us invincible and heals the monster.

<img width="582" height="292" alt="Screenshot_158" src="https://github.com/user-attachments/assets/338acb6a-a4dd-4859-b767-64fba5f3ede1" />

# first exploit
There are 2 types of bytes: unsigned byte and signed byte. an unsigned byte only contains positive numbers and can reach 255 at its highest. and a singed byte can hold 127 positive numbers and when it reaches 128, it become -128. in the game the health is stored in a SIGNED byte, so if we somehow make the monster hold more than 127, itll get minus health and we will win. in order to do that, we can use the "holy shield" because the monster heals each time we use it. so if we will use it enough times it will surpass. we will also have to use clarity because we need to regenerate mana. 

<img width="611" height="874" alt="Screenshot_160" src="https://github.com/user-attachments/assets/82038ebf-554a-4435-9fed-653b728a46f9" />

as you can see, if we do it enough times we will surpass 127 right before we lost all our health and defeated.


# second exploit
this is a basic use after free in the function PriestAttack, no matter the outcome, the allocation on the heap of the monster details will be freed. if we win the game, we will get to input our name into a new allocated memory on the heap, which will end up on the exact chunk the monster details was stored.
<img width="561" height="138" alt="Screenshot_161" src="https://github.com/user-attachments/assets/d0bf6981-101b-4e85-8c61-17fbb544bb06" />

immidiately after, the program calls the function that was previous placed in the first 4 bytes on the monster details array on the heap. meaning that the function will now JUMP to the FIRST FOUR BYTES WE ENTER. which will obviously be the system /bin/sh in the secert level.
