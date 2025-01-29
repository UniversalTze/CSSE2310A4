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

## CrackClient Parameters
Crackclient program is to accept command line arguments as follows: **./crackclient portnum [jobfile]**. 

- The mandatory portnum argument indicates which localhost port crackserver is listening on – either numerical or the name of a service. The optional jobfile argument specifies the name of a file to be used as input commands. If not specified, then crackclient is to read input from stdin.
### Behaviour (Early Exits)
- If an incorrect number of command line arguments are provided then crackclient should emit the following message: **"Usage: crackclient portnum [jobfile]"** (terminated by a newline) to stderr and exit with status 1.
- If a job file is specified, and crackclient is unable to open it for reading, crackclient shall emit the following message **"crackclient: unable to open job file "jobfile""** (terminated by newline) to stderr and exit with status 2. Jobfile is replaced by the name of the specified file. Note that the file name is enclosed in double quote 102 characters.
- If crackclient is unable to connect to the server on the specified port (or service name) of localhost, it shall emit the following message: **"crackclient: unable to connect to port N"** (terminated by a newline) to stderr and exit with status 3. N should be replaced by the argument given on the command line. (may be a non-numerical string.).
### Behaviour (Runtime)
- connect to the server on the specified port number (or service name)
- read commands either from the jobfile, or stdin, and processes them.
- when EOF is received on the input stream (job file or stdin), crackclient shall close any open network connections, and terminate with exit status 0.
- If the network connection to the server is closed (e.g. crackclient detects EOF on the socket), then crackclient shall emit the following message: **"crackclient: server connection terminated"** to stderr and terminate with exit status 4. 

Upon sending a command to the server, crackclient shall wait for a single line reply, and interpret it as follows: 
- Response ":invalid" → emit the text: **"Error in command"** to stdout.
• Response ":failed" → emit the text: **"Unable to decrypt"** to stdout.
• Otherwise, the raw output received from the server shall be output to stdout.
(Photos of behaviour will be posted down below). (link it here).

## CrackServer
Crackserver is a networked, multithreaded password cracking server, allowing clients to connect and provide encrypted ciphertext for cracking, and also allows clients to provide plaintext passwords for encrypting. All communication between clients and the server is over TCP.
## Parameters
Your crackserver program is to accept command line arguments as follows: **./crackserver [--maxconn connections] [--port portnum] [--dictionary filename]**
Program accepts up to three optional arguments (with associated values) – (any order). The connections argument, if specified, indicates the maximum number of simultaneous client connections to be permitted. If this is zero or missing, then there is no limit to how many clients may connect (be reasoanble). The portnum argument, if specified, indicates which localhost port crackserver is to listen on. If the port number is absent or zero, then crackserver is to use an ephemeral port. The dictionary filename argument, if specified, indicates the path to a plain text file containing one word or string per line, which represents the dictionary that crackserver will search when attempting to crack passwords. If not specified, crackserver shall use the system dictionary file /usr/share/dict/words.
### Behaviour: 
