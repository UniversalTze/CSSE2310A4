//Author: Tze Kheng Goh 
// Lets get cooking 
// Client server

#define PORT_INDEX 1
#define NO_OP_COM 2
#define OP_COM 3

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <csse2310a3.h>
#include <csse2310a4.h>
#include <netdb.h>

//global constant for invalid commands sent back from server
const char* invalid = ":invalid"; 
//global constant for failed command sent back from server
const char* failed = ":failed"; 

//enum used to identify if Reader struct is readind or not
enum ReadingStatus { 
    FALSE = 0, TRUE = 1,
};

//enum used for exit status for early exit or valid exit
enum ExitStatus { 
    USAGEERROR = 1, FILEJOBERR = 2, CONNECTION_ERROR = 3, 
    TERMINATED_CONNECTION = 4, NOERROR = 0,
};

//Client struct that holds port number and a place to read data from
typedef struct { 
    const char* portnum; 
    FILE* filetorun; 
} Client;

//Reader struct that hold a file descriptor and a int that represents 
//a boolean value
typedef struct { 
    int isreading; 
    int readfd;
} Reader; 

Client* check_com_line(int argc, char** argv); 
void connection_err(Client* faultyclient);
void process_client(Client* customer); 
void read_server(Reader* reader, FILE* receiving); 
void input_output_server(Client* validclient, int* writefd, Reader* readfd); 
void connection_closed(Client* client, Reader* reader, FILE* sender);

int main(int argc, char** argv) {
    Client* serverclient = check_com_line(argc, argv);
    process_client(serverclient); 
    free(serverclient);

    exit(NOERROR);
}

/* check_com_line() 
 *------------------
 *
 * This function checks for any invalid arguments. Invalid arguments occur: 
 * when number of arguments is below 2 or above 3. Job file is an optional 
 * argument. It will also fail if job file is not "local host", or a integer. 
 * Additional checks on the validity of the jobfile is checked (if given). 
 * The job file must exist and must have read privelleges. If all checks are
 * passed, a pointer to a populated Client struct will be returned. 
 *
 * numarguments: An integer that represents number of arguments on command 
 * line.
 * arguments: List of arguments given on the command line. 
 *
 * Returns: A pointer to a populated Client struct that has a valid File*
 * and a valid port number. 
 *
 * Errors: Will exit(1) if no portnum or more 3 arguments are given on 
 * command line. 
 * Will exit(2) if jobfile does not exist or cannot be read from. 
 *
 **/ 
Client* check_com_line(int numarguments, char** arguments) { 
    FILE* jobfile; 

    //checks for correct number of arguments. 
    if (numarguments < NO_OP_COM) { 
        fprintf(stderr, "Usage: crackclient portnum [jobfile]\n");
        exit(USAGEERROR); 
    } 
    if (numarguments > OP_COM) { 
        fprintf(stderr, "Usage: crackclient portnum [jobfile]\n");
        exit(USAGEERROR);
    } 
    bool opfile = false; 
    if (numarguments == OP_COM) { 
        //checks if file given on command line is valid
        int fileindex = OP_COM - 1; 
        jobfile = fopen(arguments[fileindex], "r"); 
        if (!jobfile) { 
            fprintf(stderr, "crackclient: unable to open job file "); 
            fprintf(stderr, "\"%s\"\n", arguments[fileindex]); 
            exit(FILEJOBERR);
        }
        opfile = true;
    }
    Client* clientele = malloc(sizeof(Client) * 1); 
    //malloc space for a client struct. 

    if (opfile) { // if optional file set Client's FILE* to point at it. 
        clientele->filetorun = jobfile; 
    } else { 
        //sets client struct file* variable to NULL if no jobfile present
        clientele->filetorun = NULL; 
    }
    clientele->portnum = arguments[PORT_INDEX];
    return clientele;
}

/* connection_err() 
 *-----------------
 *
 * This function will be called when client is unable to connect to 
 * the port number of host name specified on the command line. 
 *
 * faultyclient: A pointer to a faulty client as it hasn't passed all 
 * the valid checks. 
 *
 * Returns: void
 *
 * Errors: Exit(3) due to client being unable to connect to specified 
 * port number or host name. 
 *
 **/
void connection_err(Client* faultyclient) { 
    fprintf(stderr, "crackclient: unable to connect to port %s\n", 
            faultyclient->portnum); 
    if ((faultyclient->filetorun) != NULL) { 
        fclose(faultyclient->filetorun);
    }
    free(faultyclient); //free allocated memory
    exit(CONNECTION_ERROR);  
}

/* process_client() 
 *-----------------
 *
 * This function is used to connect the client either to local host or 
 * the port number given on the command line. If connection is not 
 * established, connection_err is called. If connection has been established
 * function will call input_output_server() to start commmunication 
 * between client and server. 
 *
 * customer: A pointer to a populated Client Struct. 
 *
 * Returns: void
 *
 **/
void process_client(Client* customer) {
    struct addrinfo* ai = 0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;        // IPv4, for generic could use AF_UNSPEC
    hints.ai_socktype = SOCK_STREAM;
    int err;
    if ((err = getaddrinfo("localhost", customer->portnum, &hints, &ai))) {
        freeaddrinfo(ai);
        connection_err(customer); 
        // connection error when attempting to connect to localhost
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0); // 0 == use default protocol
    if (connect(fd, ai->ai_addr, sizeof(struct sockaddr))) {
        freeaddrinfo(ai);
        connection_err(customer);
        //connection error when attempting to connect to port num
    }
    //connection has been established. 
    Reader* readthread = malloc(sizeof(readthread) * 1); 
    readthread->readfd = fd; 
    readthread->isreading = TRUE; 


    int writefd = dup(fd);
    input_output_server(customer, &writefd, readthread); 

    free(readthread);
}

/* read_server()
 *--------------
 * 
 * This function will read the output from the server and redirect it 
 * to standard out. Each line printed to standard out is seperated by new 
 * line character. If ":invalid" is received, then "Error in command" is 
 * printed to standardout. If ":failed" is received then "Unable to decrypt" 
 * is printed to standard out. Else the message received from server is 
 * printed to standard out. 
 *
 * reader: A pointer to a valid and populated reader struct. 
 * receiving: An opened file pointer used to read outputs from server. 
 *
 * Returns: void
 *
 **/
void read_server(Reader* reader, FILE* receiving) { 
    char* linetoread = NULL; 
    char* linetoprint = NULL; 
    
    linetoread = read_line(receiving); 
    if (linetoread == NULL) { 
        //connection has been closed by the server.
        fclose(receiving); 
        reader->isreading = FALSE;
    } else { 
        if (!strcmp(linetoread, invalid)) { 
            linetoprint = "Error in command";  
        } else if (!strcmp(linetoread, failed)) { 
            linetoprint = "Unable to decrypt"; 
        } else {
            linetoprint = linetoread;
        }
        fprintf(stdout, "%s\n", linetoprint); 
        fflush(stdout);
        linetoprint = NULL; 
        free(linetoread); 
    }
}

/* input_output_server() 
 *----------------------
 *
 * This function is used to handle the communication between client and 
 * server. It will write the messages from standard in or from a job file to
 * the server. It will then call read_server to read output from server. 
 * This function will call connection_closed() which will exit if the 
 * connection between client and server has been terminated. 
 *
 * validclient: pointer to a valid and populated client struct. 
 * writefd: file descriptor used to write to the server. 
 * read: pointer to a valid and populated reader struct. 
 *
 * Returns: void
 *
 **/
void input_output_server(Client* validclient, int* writefd, Reader* read) { 
    FILE* sending = fdopen(*writefd, "w"); //use file I/O to send data
    FILE* reading = fdopen(read->readfd, "r");

    FILE* inputtosend; 

    if (!validclient->filetorun) { //no job file given on command line (NULL)
        inputtosend = stdin; 
    } else { 
        inputtosend = validclient->filetorun; 
    } 
    char* processline = NULL; 
    while ((processline = read_line(inputtosend))) { 
        if (processline[0] == '#' || !(strlen(processline))) { 
            //skip line if empty or has a hashtag as its first character
            free(processline); 
            continue;
        }
        //valid line, send it to server
        fprintf(sending, "%s\n", processline); 
        fflush(sending); 
        free(processline); //free allocated mem from read_line

        read_server(read, reading); 
        // check if reader is still reading 
        if (!(read->isreading)) {  
            inputtosend = NULL; 
            connection_closed(validclient, read, sending);
        }
    }
    inputtosend = NULL; 
    fclose(sending); 
}

/* connection_closed() 
 *--------------------
 * 
 * This function is used to process an exit when a connection has been 
 * closed between client and server. It will free all malloc'ed memory and 
 * close necessary file descriptors. 
 *
 * client: pointer to a valid and populated client struct. 
 * reader: pointer to a valid and populated reader struct. 
 * sending: File pointer that is used to read outputs from server. 
 *
 * Returns: void
 *
 * Errors: exit(4) when client and server connection has been terminated. 
 **/
void connection_closed(Client* client, Reader* reader, FILE* sending) { 
    fclose(sending); 
    free(client); 
    free(reader);
    fprintf(stderr, "crackclient: server connection terminated\n"); 
    exit(TERMINATED_CONNECTION);
}

