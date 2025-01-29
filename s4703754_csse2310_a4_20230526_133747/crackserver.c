//Author: Tze Kheng Goh
// Crack Server File 

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <csse2310a3.h>
#include <csse2310a4.h>
#include <netdb.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <crypt.h>
#include <semaphore.h>
#include <signal.h>

#define NUM_DELIMETER_CLIENT_COM 3
#define LENGTH_NO_OPCOM 1
#define LENGTH_ONE_OPCOM 3
#define LENGTH_TWO_OPCOM 5
#define LENGTH_ALL_OPCOM 7
#define ZEROTH_NUM 0
#define MAX_PORTNUM 65535
#define RANGE_PORTNUM 1024
#define DICT_BUFFER 10
#define WORD_LENGTH 8
#define LINE_BUFFER 20

//Valid length of commands sent from client
const int validClientLen = 3; 
//Used to ensure that --commands on command line are in an odd index
const int checkEven = 2; 
//Used to extract plain text index when dealing with crypt com from client  
const int textIndex = 1; 
//Extract salt passage when dealing with crypt com from client
const int saltIndex = 2; 
//Ensures salt messages are 2 characters long
const int saltLength = 2; 
//used to extract the cipher text when dealing with crack from client
const int cipherTextindex = 1; 
//Ensures cipher messages are 13 characters long
const int ciphertLen = 13; 
//Extracts the num of threads client wants to use when cracking encryption
const int numThreadindex = 2; 
//Specifies the least amount of threads a user can ask for
const int minCrackThreads = 1; 
//Specifies the most amount of threads a user can ask for
const int maxCrackThreads = 50; 
//Specifies the zero port if --port command was not given on command line
const char* zeroPort = "0"; 
//Set command counters to this value if "--command" has not given on com line
const int noIndex = -1; 
//Used to test to see if commands are given more than once
const int singular = 1;
//Used for conversions in strtol (final parameter)
const int decimal = 10;
//Buffer used to specify the space needed to store string when encrypting
const int encryptBuffer = 14; 
//Max connections command argument const
const char* maxCommand = "--maxconn"; 
//Port number command const
const char* portCommand = "--port"; 
//dictionary command const
const char* dictCommand = "--dictionary"; 
//crack command const
const char* crackCom = "crack"; 
//crypt command const
const char* encrypt = "crypt"; 
//invalid message const
const char* incorrect = ":invalid"; 
//failed message const
const char* failure = ":failed";

//enums for the early exit statuses and valid exit status
enum ExitStatus { 
    USAGEERROR = 1, FILEJOBERR = 2, EMPTY_DICTIONARY = 3, 
    CONNECTION_ERROR = 4, NOERROR = 0,
};

//enums for number of optional commands
enum OpCommands { 
    ONECOM = 1, TWOCOM = 2, ALLCOM = 3,
};

//Dictionary struct that hold number of words and a list of words. 
typedef struct { 
    int numWords; 
    char** possibleWords; 
} Dictionary; 

//Struct to hold the current stats of the server. These stats include: 
//connected clients, completed clients, crack requests, failed crack 
//requests, succesful crack requests and crypt_r calls. 
typedef struct { 
    int connectedClients; 
    int completedClients; 
    int crackCom; 
    int failedCracks; 
    int succCracks; 
    int cryptCom; 
    long int cryptfuncCalls; 
    pthread_mutex_t lockstats; 
    sigset_t* signal; 
} Statistics;

//Server struct that hold a integer representing max connections, a port num 
//string, file name string, dictionary pointer, a pointer to a fd, 
//and a pointer to a semaphore. 
typedef struct { 
    int maxconnections; 
    const char* portnum; 
    char* filename; 
    Dictionary* glossary; 
    int* listeningfd; 
    sem_t* limiting; 
    Statistics* stats; 
} Server; 

//WordChecker struct that hold an ending index, a starting index in dictionary
//, a pointer to a dictionary struct, a pointer to a integer, a mutex, a 
//string that represents decrypted string, a string that is the salt used 
//to encrypt and the encrypted message
typedef struct { 
    int endPoint; 
    int startingpoint; 
    Dictionary* lookup; 
    volatile int* found; 
    pthread_mutex_t lock; 
    char* decrypt; 
    char* saltMess;
    char* encrypted; 
    Statistics* tracker; 
} WordChecker;

void* signal_handle(void* arg);
Server* set_up_server(int args, char** listarguments); 
void process_early_exit(); 
bool process_com_line(int numargs, char** arguments); 
bool check_each_com(int numargs, char** arguments); 
bool check_max_connections(int* maxcomIndex, char** commands); 
bool check_portnum(int* maxcomIndex, char** commands);
FILE* check_dictionary_file(Server* curServer); 
Dictionary* parse_dictionary(FILE* dictpointer, Server* currentServer); 
void free_all_mem(Server* closeserver);
Statistics* init_statistics(); 
int get_listenfd(Server* validServer); 
void connection_error(Server* invalidserver); 
void process_connections(int fdServer, Server* server); 
void* client_thread(void*);
bool check_valid_input_client(char** splitline, Server* operator); 
bool check_crypt_input(char** splitLine);
bool check_crack_input(char** clientInput);
char* encrypt_data(char** toencrypt, Server* crackserver); 
char* decrypt_data(char** splitargs, Server* connection); 
void* crack_dict(void* arg);
void* decrypt_cipher(void* arg); 

//main function
int main(int argc, char* argv[]) { 
    bool valid = process_com_line(argc, argv); 
    if (!valid) { 
        process_early_exit(); 
    }

    Server* validServer = set_up_server(argc, argv);
    FILE* dictionary = check_dictionary_file(validServer);
    validServer->glossary = parse_dictionary(dictionary, validServer); 

    Statistics* record = init_statistics(); 
    validServer->stats = record; 

    sigset_t sigmasks;
    record->signal = &sigmasks; 
    sigemptyset(record->signal); 
    sigaddset(record->signal, SIGHUP); 


    pthread_t signalHandler; 
    pthread_sigmask(SIG_BLOCK, record->signal, NULL);
    pthread_create(&signalHandler, 0, signal_handle, record); 
    pthread_detach(signalHandler); 

    int listenSocket = get_listenfd(validServer); 
    process_connections(listenSocket, validServer); 

    free_all_mem(validServer); 
    free(record); 

    exit(NOERROR);
}

/* signal_handle() 
 *----------------
 *
 * This function is a thrread function that will wait until a SIGHUP is sent. 
 * This function will then print the appropriate messages when a SIGHUP 
 * has been sent. 
 *
 * arg: a void pointer that has been casted on a pointer to a statistic struct
 *
 * Returns: void
 *
 **/ 
void* signal_handle(void* arg) { 
    Statistics* record = (Statistics*) arg; 
    int wait; 

    while (1) { 
        sigwait(record->signal, &wait);  
        fprintf(stderr, "Connected clients: %d\n", record->connectedClients); 
        fprintf(stderr, "Completed clients: %d\n", record->completedClients); 
        fprintf(stderr, "Crack requests: %d\n", record->crackCom); 
        fprintf(stderr, "Failed crack requests: %d\n", record->failedCracks); 
        fprintf(stderr, "Successful crack requests: %d\n", 
                record->succCracks);
        fprintf(stderr, "Crypt requests: %d\n", record->cryptCom); 
        fprintf(stderr, "crypt()/crypt_r() calls: %ld\n", 
                record->cryptfuncCalls);
        fflush(stderr);
    }

    return NULL; 
}

/* set_up_server() 
 *----------------
 *
 * This function is used to populate a server struct. This function will 
 * populate the struct with a port number, a filename and the number of 
 * max connections. If the commands are not given on the command line, the 
 * default options will be seet for port number, filename and max connections.
 * At this point, the command line is a valid command line. It will return a
 * pointer to populated struct. 
 *
 * args: Number of arguments given on the command line. 
 * listarguments: List of arguments given on the command line. 
 *
 * Returns: Pointer to a populated Server struct. 
 *
 **/
Server* set_up_server(int args, char** listarguments) { 
    bool dictionaryflag, portnumflag, maxconnflag; 
    dictionaryflag = portnumflag = maxconnflag = false; 

    Server* currentServer = malloc(sizeof(Server)); 

    for (int counter = 0; counter < args; counter++) { 
        //checks if optional commands are given. 
        //Will set the boolean flags if given. 
        //The command line is valid when it reaches here
        if (!(strcmp(listarguments[counter], maxCommand))) { 
            currentServer->maxconnections = atoi(listarguments[counter + 1]); 
            maxconnflag = true; 
        }
        if (!(strcmp(listarguments[counter], dictCommand))) { 
            currentServer->filename = listarguments[counter + 1]; 
            dictionaryflag = true; 
        }
        if (!(strcmp(listarguments[counter], portCommand))) { 
            currentServer->portnum = listarguments[counter + 1];
            portnumflag = true; 
        }
    }
    //if optional commands are not given, the default options must be set.
    if (!(dictionaryflag)) { 
        currentServer->filename = "/usr/share/dict/words";
    }
    if (!(portnumflag)) { 
        currentServer->portnum = zeroPort; 
    }
    if (!(maxconnflag)) { 
        currentServer->maxconnections = ZEROTH_NUM; 
    }
    return currentServer;
}

/* process_early_exit()
 *---------------------
 *
 * This function is used to process an early exit when the command line 
 * is not valid. It will print the required message to standard error and 
 * exit with a status of 1. 
 *
 * Returns: void
 *
 **/
void process_early_exit() { 
    fprintf(stderr, "Usage: crackserver [--maxconn connections] "); 
    fprintf(stderr, "[--port portnum] [--dictionary filename]\n"); 
    exit(USAGEERROR);

}

/* process_com_line() 
 *-------------------
 *
 * Function is used to check if command line is valid or not. It wil return
 * true if command line is valid. Else, it will return false. 
 * This function will ensure the length of command is line is 0 or an odd
 * number that is equal to or lower than 7. If the command passes this test,
 * it wil call check_each_com() which will check the individual command 
 * line arguments. If that returns false, the function will return false. 
 *
 * numargs: Number of arguments given on the command line. 
 * arguments: List of arguments given on the command line. 
 *
 * Returns: True, if command line is valid, else false. 
 *
 **/
bool process_com_line(int numargs, char** arguments) { 
    if (numargs % checkEven == ZEROTH_NUM || numargs > LENGTH_ALL_OPCOM) { 
        //cheks if additional arguments was supplied
        return false; 
    }
    bool isvalidcoms = check_each_com(numargs, arguments);
    if (!(isvalidcoms)) { 
        return false; 
    }
    return true; 
}

/* check_each_com() 
 *-----------------
 *
 * This function will check the individual command line arguments. 
 * Command line is invalid if: 
 * any of --maxconn, --port or --dict does not have an associated value
 * argument
 * the maximum connections argument (if present) is not a non-negative 
 * integer
 * the port number argument (if present) is not an integer value, or is an 
 * integer value and is not either zero, or in the range of 1024 to 65535 
 * inclusive
 * any of the arguments is specified more than once
 *
 * numargs: Number of arguments given on the command line. 
 * arguments: List of arguments given on the command line. 
 *
 * Returns: True, if the command line arguments is valid, else false. 
 *
 **/
bool check_each_com(int numargs, char** arguments) {  
    int dictcomCounter, maxcomCounter, portcomCounter; 
    int dictcomIndex, maxcomIndex, portcomIndex; 
    dictcomCounter = maxcomCounter = portcomCounter = 0; 
    dictcomIndex = maxcomIndex = portcomIndex = noIndex; 
    for (int index = 0; index < numargs; index++) { 
        //will increment a spefic commands counter depending on instruction 
        //that appears on command line. 
        if (!(strcmp(arguments[index], maxCommand))) { 
            maxcomCounter++; 
            maxcomIndex = index; //set index to latest appearance of command
        }
        if (!(strcmp(arguments[index], dictCommand))) {
            dictcomCounter++;
            dictcomIndex = index; 
        }
        if (!(strcmp(arguments[index], portCommand))) { 
            portcomCounter++; 
            portcomIndex = index; 
        }
    }
    int comCount = dictcomCounter + maxcomCounter + portcomCounter; 
    if ((numargs == LENGTH_ALL_OPCOM && comCount != ALLCOM) || 
            (numargs == LENGTH_ONE_OPCOM && comCount != ONECOM) || 
            (numargs == LENGTH_TWO_OPCOM && comCount != TWOCOM)) { 
        //check ensures that correct number optional commands are given 
        //depending on the number of inputs.
        return false;
    }
    if (dictcomCounter > singular || maxcomCounter > singular || 
            portcomCounter > singular) { 
        //checks for duplicated arguments was specified.
        return false; 
    } 
    if ((dictcomIndex % checkEven == ZEROTH_NUM) || (maxcomIndex % checkEven 
            == ZEROTH_NUM) || (portcomIndex % checkEven == ZEROTH_NUM)) { 
        //checks if the index of optional commands are even. If they are even, 
        //then an optional command will not have an associated value. 
        return false; 
    }
    if (maxcomIndex > noIndex) { 
        //check correctmax connection com and arg is given
        return check_max_connections(&maxcomIndex, arguments);
    }
    if (portcomIndex > noIndex) { //check correct port num when --port given
        return check_portnum(&portcomIndex, arguments);
    }
    return true; //no optional command given so its valid.  
}

/* check_max_connections() 
 *------------------------
 *
 * This function will check if the max connections is an integer and 
 * non negative if given on command line. 
 *
 * maxcomIndex: Is the index of the max command index on the line. 
 * commands: List of arguments given on the command line. 
 *
 * Returns: True if the max command value argument is valid, Else, false. 
 *
 * Errors: If associated value with max connections is not valid, function
 * will return false, which will cause program with an exit status of 1. 
 *
 **/
bool check_max_connections(int* maxcomIndex, char** commands) {
    int maxconnectionsPos = ++*maxcomIndex; 
    char* ending; 
    long connections = strtol(commands[maxconnectionsPos], &ending, decimal);
    if (*ending != '\0') { 
        //argument given includes characters that aren't numbers. 
        return false; 
    }
    if (connections < ZEROTH_NUM) { 
        //connection was a negative integer. 
        return false; 
    }
    return true; 
}

/* check_portnum() 
 *----------------
 * 
 * This function will check if the value associated with port num command 
 * is valid. A port num is not valid if: 
 * is not an integer value
 * is an integer that is not zero and is not in the range of 1024 to 
 * 65535 (inclusive).If valid, a boolean value of true is returned. Else, 
 * false is returned. 
 *
 * portcomIndex: A pointer to an integer that represents the port command 
 * index in the array (command line).  
 * commands: List of arguments given on the command line. 
 *
 * Returns: True if port number is valid, else false. 
 *
 **/
bool check_portnum(int* portcomIndex, char** commands) {
    int portIndex = ++*portcomIndex; 
    char* result; 
    long finalport = strtol(commands[portIndex], &result, decimal); 

    if (*result != '\0') {   
        //argument given includes characters that aren't numbers. 
        return false; 
    }
    if ((finalport != ZEROTH_NUM) && ((finalport < RANGE_PORTNUM) || 
            (finalport > MAX_PORTNUM))) { 
        //ensures portnum is 0 or in the given range (1024-65535)
        return false; 
    }
    return true; 
}

/* check_dictionary() 
 *-------------------
 *
 * This function will ensure that the dictionary (if given), is able to be
 * opened and can be read. If the dictionary does not exist or cannot 
 * be read from, the function will exit with a status of 2. If valid, a 
 * File pointer to the opned dictionary will be returned. 
 *
 * curServer: is a pointer to a populated and malloc'ed server struct, which 
 * has the filename of the dictionary attached to it. 
 *
 * Returns: A file pointer to the opened dictionary. 
 *
 * Errors: Will exit with a status of 2 if file does not exist or cannot 
 * be read from. 
 *
 **/
FILE* check_dictionary_file(Server* curServer) { 
    FILE* dictpointer = fopen(curServer->filename, "r");
    if (dictpointer == NULL) { 
        fprintf(stderr, "crackserver: unable to open dictionary file "); 
        fprintf(stderr, "\"%s\"\n", curServer->filename); 
        free(curServer); 
        exit(FILEJOBERR);
    }
    return dictpointer;
}

/* parse_dictionary()
 *-------------------
 * 
 * This function will be used to populate and malloc'ed Dictionary struct. If 
 * dictionary is valid a pointer of this new malloc'ed struct will be 
 * returned. If the dictionary has no valid words, empty lines or all lines 
 * that begin with a "#", this function will exit with a status of 3. 
 *
 * Returns: A dictionary pointer to a populated and malloc'ed struct. 
 *
 * Errors: If dictionary is invalid, function will exit with a status of 3. 
 *
 **/
Dictionary* parse_dictionary(FILE* dictpointer, Server* currentServer) { 
    char* line = NULL; 
    Dictionary* words = malloc(sizeof(Dictionary));  
    words->possibleWords = malloc(sizeof(char*) * DICT_BUFFER); 
    words->numWords = 0; 
    while ((line = read_line(dictpointer))) { 
        int parser; 
        for (parser = 0; line[parser] != '\0'; parser++) { 
            //check length or string
            //empty body
        } 
        if (parser > WORD_LENGTH) { 
            free(line); 
            continue; 
        }
        //length of read word is WORD_LENGTH (8) or below
        words->possibleWords[words->numWords] = line; 
        words->numWords++; 
        if (words->numWords > ZEROTH_NUM && words->numWords % DICT_BUFFER 
                == ZEROTH_NUM) {
            //reallocate if malloc space has been occupied
            words->possibleWords = realloc(words->possibleWords, sizeof(char*)
                    * (words->numWords * 2)); 
        }
    }
    //checks if possiblewords is empty (no valid words or no words in file) 
    if (words->numWords == ZEROTH_NUM) { 
        free(words->possibleWords); 
        free(words); 
        free(currentServer); 
        fprintf(stderr, "crackserver: no plain text words to test\n"); 
        exit(EMPTY_DICTIONARY);
    }
    fclose(dictpointer); 
    return words; 
}

/* free_all_mem() 
 *---------------
 *
 * This function will free all memory malloc for the server. 
 *
 * closeServer: Pointer to populated server struct that holds all the 
 * malloc'ed memory. 
 *
 * Returns: void
 *
 **/
void free_all_mem(Server* closeServer) { 
    for (int count = 0; count < closeServer->glossary->numWords; count++) {
        free(closeServer->glossary->possibleWords[count]); 
    }
    free(closeServer->glossary->possibleWords); 
    free(closeServer->glossary); 
    free(closeServer); 
}

/* init_statistics() 
 *------------------
 * 
 * The function will initialise a statistics struct and return a pointer to 
 * the struct. The struct will also be malloc'ed. The struct will keep track 
 * of the amount of clients connected at this instant, the number of 
 * completed clients, the number of crack requests, the number of failed 
 * crack requests, the number of succesful cracks, the number of crypt 
 * requests and the number of crypt, crypt_r calls. 
 *
 * Returns: A pointer to a initalised and malloc'ed Statistics struct. 
 *
 **/ 
Statistics* init_statistics() { 
    Statistics* statchecker = malloc(sizeof(Statistics)); 
    statchecker->connectedClients = 0; 
    statchecker->completedClients = 0; 
    statchecker->crackCom = 0; 
    statchecker->failedCracks = 0; 
    statchecker->succCracks = 0; 
    statchecker->cryptCom = 0;
    statchecker->cryptfuncCalls = 0; 
    pthread_mutex_init(&statchecker->lockstats, NULL); 
    return statchecker; 
}

/* get_listenfd()
 *---------------
 * 
 * The function will open a connection socker for the server to listen in on. 
 * It will return a file descriptor that represents the fd for where the 
 * server is listening on. This is how the server can communicate with 
 * the client. If connection cannot be established, the function will call 
 * connection_error() which will exit with a status of 3. 
 *
 * server: Pointer to a malloc'ed and populated server struct. 
 *
 * Returns: A file descriptor that will be where the server will listen in 
 * and process input from client. 
 *
 * Errors: If connection is established, program will exit with a status of 
 * 3. 
 *
 **/
int get_listenfd(Server* server) { 
    struct addrinfo* ai = 0; 
    struct addrinfo hints;
    
    memset(&hints, 0, sizeof(struct addrinfo)); 
    hints.ai_family = AF_INET;        // IPv4  for generic could use AF_UNSPEC
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;  
    // Because we want to bind with it on all of our interfaces 
    // (if first argument to getaddrinfo() is NULL)
    int err;
    if ((err = getaddrinfo(NULL, server->portnum, &hints, &ai))) {
        freeaddrinfo(ai); 
        connection_error(server); // could not work out the address
    } 
    // create a socket and bind it to a port
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);// 0 = use default protocol
    
    int optVal = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optVal, 
            sizeof(int)) < 0) {
        //allow address (port number) to be reused again.
        connection_error(server); 
    }
    if (bind(listenfd, ai->ai_addr, sizeof(struct sockaddr))) {
        connection_error(server); 
    } 
    // Which port did we get?
    struct sockaddr_in ad;
    memset(&ad, 0, sizeof(struct sockaddr_in));
    socklen_t len = sizeof(struct sockaddr_in);
    if (getsockname(listenfd, (struct sockaddr*)&ad, &len)) {
        connection_error(server); 
    }
    fprintf(stderr, "%u\n", ntohs(ad.sin_port)); //port num we got

    if (!server->maxconnections) { 
        //if max connections specified is 0, set it to MAXCONN
        server->maxconnections = SOMAXCONN; 
    }
    if (listen(listenfd, server->maxconnections)) {     
        // allow up to number of connections specified before queue. 
        connection_error(server); 
        //error handling if listen fails. 
    }
    //listening socket fd succesfully opened 
    return listenfd;
}

/* connection_error() 
 *-------------------
 *
 * This function is called if connection to the socket cannot be established. 
 * It will print the necessary message, free the memory and exit with a 
 * status of 4. 
 *
 * invalidServer: A pointer to a malloc'ed server struct that will be freed. 
 *
 * Returns: void
 *
 * Errors: Will exit with a status of 4 as the connection cannot be 
 * established. 
 *
 **/
void connection_error(Server* invalidServer) { 
    fprintf(stderr, "crackserver: unable to open socket for listening\n"); 
    free_all_mem(invalidServer); 
    exit(CONNECTION_ERROR); 
}

/* process_connections() 
 *----------------------
 *
 * This function will process the connection between client. This is where 
 * client connections are accepted.
 *
 * fdServer: The file descriptor the function will use to listen to inputs
 * from the client. 
 * server: A pointer to a malloc'ed and populated server struct. 
 * 
 * Returns: Void 
 *
 **/
void process_connections(int fdServer, Server* server) {
    int fd;
    struct sockaddr_in fromAddr;
    socklen_t fromAddrSize;
    sem_t semaphore;
    sem_init(&semaphore, 0, server->maxconnections);
    server->limiting = &semaphore; 
    // Repeatedly accept connections and process data (capitalise)
    while (1) {
        fromAddrSize = sizeof(struct sockaddr_in);
	// Block, waiting for a new connection. (fromAddr will be populated
	// with address of client)
        fd = accept(fdServer, (struct sockaddr*)&fromAddr, &fromAddrSize);
    
        if (fd < 0) {
            connection_error(server); 
        } 
        sem_wait(server->limiting); 

        server->listeningfd = malloc(sizeof(int)); 
        *server->listeningfd = fd; 
        //increment client counter
        pthread_mutex_lock(&server->stats->lockstats); 
        server->stats->connectedClients++; 
        pthread_mutex_unlock(&server->stats->lockstats); 
        
	pthread_t threadId;
	pthread_create(&threadId, 0, client_thread, server);
	pthread_detach(threadId);
    }
}

/* client_thread() 
 *----------------
 *
 * This function is a thread function that is called from process_connections
 * It will process the inout from the client and send the output to the
 * client. The output will depend on the input from client. If client input
 * is valid and the command is a crypt, it will return an encryption string. 
 * If the client input is invalid and command is crypt, it will return 
 * ":invalid". This will be the same for crack. Any invalid commands sent
 * will also lead to the same result. If a valid crack command is sent, 
 * and is succesful, the decrypted message will be sent. If unsuccesful, 
 * a ":failed" message will be sent. 
 * All messages are sent with a new line separator. 
 *
 * arg: A void pointer that is wrapped around a pointer to a malloc'ed and 
 * populated server struct. 
 *
 * Returns: void* 
 *
 **/
void* client_thread(void* arg) {
    Server* crackserver = (Server*)arg; 

    int readfromclientfd = *crackserver->listeningfd;
    int writetoclientfd = dup(readfromclientfd); 
    FILE* fromclient = fdopen(readfromclientfd, "r"); 
    FILE* writetoclient = fdopen(writetoclientfd, "w"); 

    char* linetoprocess = NULL; 
    // Repeatedly read data arriving from client 
    while ((linetoprocess = read_line(fromclient))) {
        char* linetosend = NULL; 
        char** splitdupLine = split_by_char(linetoprocess, ' ', 
                NUM_DELIMETER_CLIENT_COM); 

        if (!(check_valid_input_client(splitdupLine, crackserver))) { 
            linetosend = strdup(incorrect); 
        } else if (!(strcmp(splitdupLine[0], encrypt))) {
            linetosend = encrypt_data(splitdupLine, crackserver); 
        } else if (!(strcmp(splitdupLine[0], crackCom))) { 
            linetosend = decrypt_data(splitdupLine, crackserver); 
        }
	fprintf(writetoclient, "%s\n", linetosend); 
        fflush(writetoclient);
        free(linetoprocess); 
        free(splitdupLine); 
        free(linetosend); 
    }
    //client has exited. 
    //decrement client connection counter, and increment completed clients
    pthread_mutex_lock(&crackserver->stats->lockstats); 
    crackserver->stats->connectedClients--; 
    crackserver->stats->completedClients++; 
    pthread_mutex_unlock(&crackserver->stats->lockstats); 
        

    fclose(fromclient);
    fclose(writetoclient);
    sem_post(crackserver->limiting); 
    return NULL;
}

/* check_valid_input_client() 
 *---------------------------
 * 
 * This function will check the general tests need to check if the line sent
 * from the client is valid. If length sent by the client is not 3 or 
 * first argument of the line is not crypt or crack, or if any of 
 * the arguments are empty, it will return false. If these tests are passed, 
 * this function will call check_crypt_input() and check_crack_input. If one 
 * of those functions return, this function will return true. 
 *
 * splitLine: A string array that will hold lines that have been split 
 * using split_by_char(). 
 * operator: A pointer to a malloc'ed and populated struct. 
 *
 * Returns: True, if the client input is valid. Else, it will return false. 
 *
 **/
bool check_valid_input_client(char** splitLine, Server* operator)  { 
    int length; 
    char* empty = ""; 
    for (length = 0; splitLine[length] != NULL; length++) { 
        if (!(strcmp(splitLine[length], empty))) { 
            // if any inputs sent are the empty string
            return false; 
        }
    } 
    if (length != validClientLen) { 
        //if length is not 3
        return false; 
    }
    if ((strcmp(splitLine[0], crackCom) && strcmp(splitLine[0], encrypt))) {
        //if first argument is not 'crack' or 'crypt' 
        return false; 
    }
    if (!(strcmp(splitLine[0], encrypt))) { 
        //if command specified is crypt, increment crypt request
        pthread_mutex_lock(&operator->stats->lockstats); 
        operator->stats->cryptCom++;  
        pthread_mutex_unlock(&operator->stats->lockstats); 

        return check_crypt_input(splitLine); 
    }
    if (!(strcmp(splitLine[0], crackCom))) { 
        //if crack is specified by client, increment crack request
        pthread_mutex_lock(&operator->stats->lockstats); 
        operator->stats->crackCom++;  
        pthread_mutex_unlock(&operator->stats->lockstats); 
        return check_crack_input(splitLine); 
    }

    return true; 
}

/* check_crypt_input() 
 *--------------------
 *
 * This function will check the associated inputs when a crypt command is 
 * given from the client. For the crypt command to be valid: 
 * The salt length must be equal to 2 characters. 
 * The salt length must be within the character set mentioned in the spec. 
 * The function will return true if the assocated commands are valid. Else
 * it return false. 
 *
 * splitLine: an array of strings that has been sent from the client split 
 * into 3 arguments. 
 *
 * Returns: True if associated arguments after crypt are valid. Else, it
 * will return false. 
 *
 **/
bool check_crypt_input(char** splitLine) { 
    if (strlen(splitLine[saltIndex]) != saltLength) { 
        return false; 
    }
    for (int index = 0; index < saltLength; index++) { 
        if (splitLine[saltIndex][index] > 'z' || splitLine[saltIndex][index] < 
                '.') { 
            //checks if salt index is not between the range: '.' and 'z'
            return false; 
        }
        //salt index is between the range '.' and 'z'
        if (splitLine[saltIndex][index] >= ':' && 
                splitLine[saltIndex][index] <= '@') { 
            //if salt characters in between ':' and '@. 
            return false;
        }
        if (splitLine[saltIndex][index] >= '[' && 
                splitLine[saltIndex][index] <= '`') { 
            //if salt characters inbetween '[' and '`'.
            return false; 
        }
    }
    return true; 
}

/* check_crack_input()
 *--------------------
 *
 * This function will check if the associated crack arguments are specified. 
 * This function will return false if associated arguments with the crack 
 * command is invalid. Associated arguments are invalid if: 
 * If the crack cipher text is not exactly 13 chacracters long or 
 * if the max crack threads is not an integer or cannot be converted into 
 * an integer
 * if the number of crack threads is greater than or equal to 1 and less 
 * than or equal to 50. 
 * If the salt letters are not in the character set in the spec, return 
 * false. 
 *
 * Returns: True if associated arguments with crack are valid. Else, false. 
 *
 **/
bool check_crack_input(char** clientInput) { 
    //check length of cipher text
    if (strlen(clientInput[cipherTextindex]) != ciphertLen) { 
        return false; 
    }
    // salt characters of cipher text
    for (int index = 0; index < saltLength; index++) { 
        if (clientInput[cipherTextindex][index] > 'z' || 
                clientInput[cipherTextindex][index] < '.') { 
            return false; 
        }
        //salt indexes of cipher text is between the range '.' and 'z'
        if (clientInput[cipherTextindex][index] >= ':' && 
                clientInput[cipherTextindex][index] <= '@') { 
            //if salt characters of cipher text in between ':' and '@. 
            return false;
        }
        if (clientInput[cipherTextindex][index] >= '[' && 
                clientInput[cipherTextindex][index] <= '`') { 
            //if salt characters of cipher text inbetween '[' and '`'.
            return false; 
        }
    }
    //check num of crack threads
    char* check; 
    long int requestThread = strtol(clientInput[numThreadindex], &check, 
            decimal);
    if (*check != '\0') { 
        //if crack threads specified was not a number or a mixture of num and
        //characters
        return false; 
    }
    if (requestThread < minCrackThreads || requestThread > maxCrackThreads) { 
        return false; 
    }
    return true; 
}

/* encrypt_data() 
 *---------------
 *
 * This function will encrypt the data, sent from the client. This line 
 * is assumed to be valid as it has passed all the valid checks. This 
 * function will return a malloc'ed encrypted string. 
 * 
 * toencrypt: malloc'ed encrypted string that will be returned. 
 * crackserver: a pointer to a populated and malloc'ed server struct. 
 *
 * Returns: An encrypted and malloc'ed string. 
 *
 **/
char* encrypt_data(char** toencrypt, Server* crackserver) { 
    char* finalEncryption = malloc(sizeof(char) * encryptBuffer); 

    struct crypt_data cryptData = {0}; 

    char* salt = toencrypt[saltIndex]; 
    char* plaintext = toencrypt[textIndex]; 
    char* encryptedData = crypt_r(plaintext, salt, &cryptData);

    if (encryptedData != NULL) { 
        strcpy(finalEncryption, encryptedData); 
    }
    //sucessful encryption. 
    pthread_mutex_lock(&crackserver->stats->lockstats);  
    crackserver->stats->cryptfuncCalls++; 
    pthread_mutex_unlock(&crackserver->stats->lockstats);

    return finalEncryption; 
}

/* decrypt_data()
 *---------------
 * 
 * This function is used to decrypt data sent from the client. It will spawn
 * the numner  thread to decrypt data sent with the dictionary. It will 
 * provide each thread with the necessary variables needed to process the 
 * dictionary. This function will return a string that is either the 
 * decrypted string or a duplicate of the failed string ":failed". 
 *
 * splitargs: An array of strings that split up the line received from the 
 * client. 
 * connection: A pointer to a valid populated server struct. 
 *
 * Returns: The decrypted string if found, else a duplicate of the failed 
 * string. 
 *
 **/
char* decrypt_data(char** splitargs, Server* connection) { 
    WordChecker* threads = malloc(sizeof(WordChecker)); 
    //threads work with same struct, just different starting points. 

    threads->tracker = connection->stats; 
    int numThreads = atoi(splitargs[numThreadindex]);  
    threads->lookup = connection->glossary; 
    threads->encrypted = splitargs[cipherTextindex]; 
    threads->saltMess = malloc(sizeof(char) * (saltLength + 1));
    strncpy(threads->saltMess, threads->encrypted, 2); 
    threads->saltMess[saltLength] = '\0'; 
    
    pthread_mutex_init(&threads->lock, NULL); 
    threads->found = malloc(sizeof(int) * 1); 
    *threads->found = 0; 
    
    if (numThreads > threads->lookup->numWords) { 
        numThreads = minCrackThreads; 
    }

    pthread_t* tids = malloc(sizeof(pthread_t) * numThreads);  
    int wordsmultiplier = threads->lookup->numWords / numThreads;

    for (int index = 0; index < numThreads; index++) { 
        //if statments used to populate each WordCheck struct with 
        //correct indexes when reading dictionary. 
        if (numThreads == minCrackThreads) {  
            //checks for when to use only one thread. 
            threads->startingpoint = 0; 
            threads->endPoint = threads->lookup->numWords; 
        } else if (index != numThreads - 1) { 
            //number of threads requested is more than one. 
            threads->startingpoint = index * wordsmultiplier; 
            threads->endPoint = (index + 1) * wordsmultiplier; 
        } else { 
            //final thread
            threads->startingpoint = (index * (wordsmultiplier)); 
            threads->endPoint = threads->lookup->numWords; 
        }
        pthread_create(&(tids[index]), 0, decrypt_cipher, threads); 
    }
    for (int counter = 0; counter < numThreads; counter++) { 
        //wait for threads to finish
        pthread_join(tids[counter], NULL);
    }
    return threads->decrypt;
}

/* decrypt_chiper() 
 *-----------------
 *
 * This is a thread function which all the threads will use to decrypt the 
 * cipher text. To decypher, the text, the brute force method is used.
 * So the function will encrypt each word and will check if the encryption 
 * matches the encrypted string sent from client. If the encrypted word is 
 * found, the thread will duplicate the word in the dictionary and populate 
 * the struct variable "decrypt". it. Else, it will populate the struct with 
 * a dupped string ":failed". When the word has been found, all threads will 
 * exit appropriately. 
 *
 * arg: A void pointer that will hold a pointer to a WordChecker struct. 
 *
 * Returns: void* 
 *
 **/
void* decrypt_cipher(void* arg) { 
    //retrive pointer to WordChecker struct from a void*
    WordChecker* cracker = (WordChecker*) arg; 


    for (int index = cracker->startingpoint; index < cracker->endPoint; 
            index++) { 
        //if word has been found, tell all threads to exit
        if (*cracker->found) { 
            pthread_exit(NULL); 
        }
        //word has not been found
        struct crypt_data cryption = {0}; 
        char* checker = crypt_r(cracker->lookup->possibleWords[index], 
                cracker->saltMess, &cryption); 
        
        pthread_mutex_lock(&cracker->tracker->lockstats);  
        cracker->tracker->cryptfuncCalls++; 
        pthread_mutex_unlock(&cracker->tracker->lockstats);

        //process to occur when encryption is the same
        if (!(strcmp(cracker->encrypted, checker))) { 
            //word has been found. 
            pthread_mutex_lock(&cracker->lock); 
            cracker->decrypt = strdup(cracker->lookup->possibleWords[index]);
            *cracker->found = 1; 
            pthread_mutex_unlock(&cracker->lock); 

            //increment succesful crack counter. 
            pthread_mutex_lock(&cracker->tracker->lockstats);  
            cracker->tracker->succCracks++; 
            pthread_mutex_unlock(&cracker->tracker->lockstats);
            //only update the struct without returning anything
        }
    }
    //if encryption does not match any encryption of words found in 
    //dictionary
    
    pthread_mutex_lock(&cracker->tracker->lockstats);  
    cracker->tracker->failedCracks++; 
    pthread_mutex_unlock(&cracker->tracker->lockstats);


    pthread_mutex_lock(&cracker->lock);
    cracker->decrypt = strdup(failure); 
    pthread_mutex_unlock(&cracker->lock); 
    pthread_exit(NULL); 
}
