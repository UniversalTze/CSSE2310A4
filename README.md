# CSSE2310A4
Multi-threading and Client/Server Communication

## CrackClient && CrackServer. 
The goal of this assignment was to demonstrate skills and ability in fundamental process management and communication concepts, and to further develop your C programming skills with a moderately complex program. Areas of focus was on networking and multithreaded programming. I created two programs: Crackclient and CrackServer. CrackServer – is a network server which 4 accepts connections from clients (including crackclient). Clients connect, and provide encrypted passphrases that the server will attempt to crack (recover the original unencrypted passphrase). Clients may also request the server to encrypt passwords for later analysis. Communication between the crackclient and crackserver is over TCP using a newline-terminated text command protocol. Advanced 8 functionality such as connection limiting, signal handling and statistics reporting are also required for full 9 marks.

## Comments 
This assigment was developed in a UQ linux environment. Vim was the main application used to write code and terminal was used to navigate around files. 
To access the linux environment, a SSH or "Secure Shell" was used. For version control, SVN was used. 

## Marks 
- 60.15/65 (Autograder Score)
- Future improvements: Get 100%.

## Context on what program does
Notes: File can only be ran in UQ Linux environment through SSH as the Makefile links to libraries provided in that environment. 

## Cipher Text
Hashing is a common method of protecting sensitive data such as passwords. Instead of storing or transmitting the password itself (plaintext) where it is at risk of interception, the password is first transformed by passing it through a one-way function called a hash, yielding the ciphertext. A one-way function is one that is easy to apply in one direction (plaintext to ciphertext), but impossible to apply in the reverse.
Because hash functions are deterministic, identical passwords encrypted with a hash function yield identical ciphertext, which can assist an adversary in compromising a system. For this reason, the hashing scheme is usually extended with a method called salting. The plaintext is extended with a random value, or salt, prior to applying the hash function. The salt is stored along with the encrypted password, as both are required to verify a given password and its hash. 
libcrypt is a POSIX library that supports a wide range of hashing functions and salting schemes – in this 63 assignment you will use it in its simplest mode. Note that this mode is now considered obsolete, and should not be used for protecting data in modern systems.
The return value from crypt() is a pointer to a static buffer, so the caller must copy this before making any further calls to crypt().
- Here are some examples:
  - plaintext "foobar", salt "AA" → ciphertext "AAZk9Aj5/Ue0E"
  - plaintext "dinosaur", salt "0z" → ciphertext "0zD1fV.Yez8RI"
he crypt() family of functions is declared in <crypt.h>, and you will need to link your crackserver with the -lcrypt argument to use them in your programs.
