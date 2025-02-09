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
The crackserver program is to operate as follows: 
- If the program receives an invalid command line then it must print the message: <br>
Usage: **crackserver [--maxconn connections] [--port portnum] [--dictionary filename]** to stderr, and exit with an exit status of 1.<br>   
More Invalid command lines include:
    - any of --maxconn, --port or --dict does not have an associated value argument.
    - the maximum connections argument (if present) is not a non-negative integer.
    - the port number argument (if present) is not an integer value, or is an integer value and is not either 169 zero, or in the range of 1024 to 65535 inclusive.
    - any of the arguments is specified more than once.
    - any additional arguments are supplied.
- If the dictionary filename argument refers to a file that does not exist or cannot be opened for reading, crackserver shall emit the following error message to stderr and terminate with exit status 2: <br>
     **crackserver: unable to open dictionary file "filename"** <br>
where filename is replaced by the name of the dictionary file provided on the command line. Note that 175 the double quote characters must be present.
    - The dictionary words must be read into memory. Lines in the dictionary are terminated by newline characters (except possibly the last line) and each line (excluding that newline character) is considered to be a word.
    - Any words longer than 8 characters should be discarded, i.e. not saved into memory, as  the crypt() family of functions only considers at most 8 characters of any supplied plain text. The order of words must be preserved. It is possible the dictionary may contain duplicate words and these should be preserved also. You may assume that words in the dictionary are no longer than 50 characters.
    - Your crackserver must read the dictionary only once.
- If the dictionary contains no words that are 8 characters long or shorter, then crackserver shall emit the following error message to stderr and terminate with exit status 3:
     **crackserver: no plain text words to test**
- If portnum is missing or zero, then crackserver shall attempt to open an ephemeral localhost port for listening. Otherwise, it shall attempt to open the specified port number. If crackserver is unable to listen on either the ephemeral or specified port, it shall emit the following message to stderr and terminate with exit status 4:
     **crackserver: unable to open socket for listening**
- Once the port is opened for listening, crackserver shall print to stderr the port number followed by a single newline character and then flush the output. In the case of ephemeral ports, the actual port number obtained shall be printed, not zero.
-  Upon receiving an incoming client connection on the port, crackserver shall spawn a new thread to handle that clienT.
- If specified (and implemented), crackserver must keep track of how many active client connections exist, and must not let that number exceed the connections parameter.
- Note that all error messages above must be terminated by a single newline character.
- Note that your crackserver must be able to deal with any clients using the correct communication protocol, not just crackclient. Testing with netcat is highly recommended.
#### Client Handling Threads
- A client handler thread is spawned for each incoming connection. This client thread must then wait for commands from the client, one per line, over the socket. The exact format of the requests is described in the Communication protocol section below.
- As each client sends crack requests to crackserver, it the client thread shall spawn threads to perform the brute-force password cracking action against the dictionary. The number of cracking threads spawned per crack request will be specified as part of the request. Even if only one cracking thread is requested, the client thread must spawn an additional thread to do the cracking.
- crypt requests from the client must be handled directly in the client handling thread if you wish – it is not computationally expensive and there is no need to spawn an additional thread for this operation.
- Due to the simultaneous nature of the multiple client connections, your crackserver will need to ensure mutual exclusion around any shared data structure(s) to ensure that these do not get corrupted. Once the client disconnects or there is a communication error on the socket then the client handler thread is to close the connection, clean up and terminate. Other client threads and the crackserver program itself must continue uninterrupted.
#### Password Cracking Algorithm

{Insert photo here} 

#### 
