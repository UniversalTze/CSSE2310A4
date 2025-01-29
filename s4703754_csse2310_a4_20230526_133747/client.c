// A4 client program
// Pocholo Sarmiento

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <csse2310a3.h>
#include <csse2310a4.h>
#include <netdb.h>

#define PORTNUM_INDEX 1
#define NAME_INDEX 2

#define DEFAULT_PROTOCOL 0

enum ExitCodes {
    OK = 0,
    USAGE_ERROR = 1,
    INVALID_ARG_ERROR = 2,
    CONNECTION_ERROR = 3,
    SERVER_TERMINATED_ERROR = 4
};

/**
 * Settings struct to store program settings
 */
typedef struct {
    // portnumber for client to connect to
    char* portnum;
    // name of client
    char* name;
    // topics that the client will sub to
    char* topics[];
} Settings;

Settings* parse_command_line(char* argv[], int argc);
bool is_valid_arg(char* name);
void usage_error();
void invalid_name_error();
void invalid_topic_error();
void connection_error(char* port);
void setup_client(Settings* settings);
void* receive_server(void* arg);

int main(int argc, char** argv) {
    Settings* settings = parse_command_line(argv, argc);

    setup_client(settings);
    return OK;
}

/**
 * parse_command_line()
 * 
 * Parses command line argument to set portnum, name and topics
 * 
 * @param argv command line arguments to parse
 * @param argc number of command line arguments
 * @return Settings* struct pointer containing portnum, name and topics
 * Errors: will output and exit with
 *  - usage error if insufficent comand line arguments are provided
 *  - invalid name error if name argument contains spaces, colons, or new line
 *    or if empty
 *  - invalid topic error if topic argument contains spaces, colons, 
 *    or new line, or if empty
 */
Settings* parse_command_line(char* argv[], int argc) {
    // Check correct number of args
    if (argc < 3) {
        usage_error();
    }
    int topicSize = argc - 2; // leave extra to NULL terminate

    Settings* settings = malloc(sizeof(Settings) + sizeof(char*[topicSize]));

    int currentTopic = 0;
    for (int i = 1; i < argc; i++) {
        switch (i) {
            case PORTNUM_INDEX:
                settings->portnum = argv[i];
                break;
            case NAME_INDEX:
                // check if argument is valid
                if (is_valid_arg(argv[i])) {
                    // set settings name
                    settings->name = argv[i];
                } else {
                    free(settings);
                    invalid_name_error();
                }
                break;
            default:
                // check if argument is valid
                if (is_valid_arg(argv[i])) {
                    // add topic to array
                    settings->topics[currentTopic] = argv[i];
                    currentTopic++;
                } else {
                    free(settings);
                    invalid_topic_error();
                }
                break;
        }
    }

    // terminate topics array with NULL
    settings->topics[topicSize-1] = NULL;

    return settings;
}

/**
 * is_valid_arg()
 * 
 * Check if string is a valid argument
 * 
 * @param name string to check
 * @return true does not contain spaces, colons, newlines and is not empty 
 */
bool is_valid_arg(char* name) {
    return !strchr(name, ' ') && !strchr(name, ':') && !strchr(name, '\n')
            && name[0] != '\0';
}

/**
 * usage_error()
 * 
 * Called when usage error occurs when parsing command line arguments
 */
void usage_error() {
    fprintf(stderr, "Usage: psclient portnum name [topic] ...\n");
    exit(USAGE_ERROR);
}

/**
 * invalid_name_error()
 * 
 * Called when invalid name found when parsing command line arguments
 */
void invalid_name_error() {
    fprintf(stderr, "psclient: invalid name\n");
    exit(INVALID_ARG_ERROR);
}

/**
 * invalid_topic_error()
 * 
 * Called when invalid topic found when parsing command line arguments
 */
void invalid_topic_error() {
    fprintf(stderr, "psclient: invalid topic\n");
    exit(INVALID_ARG_ERROR);
}

/**
 * connection_error()
 * 
 * Called when unable to conenct to the server on the specified port (or
 * service name) of local host
 * 
 * @param port string of port
 */
void connection_error(char* port) {
    fprintf(stderr, "psclient: unable to connect to port %s\n", port);
    exit(CONNECTION_ERROR);
}

/**
 * setup_client()
 * 
 * Set up client to connect to server. If successful, send name and sub 
 * commands based on settings input.
 * 
 * @param settings struct of the program
 * Errors: connection error occurs if client is unable to connect to server
 */
void setup_client(Settings* settings) {
    struct addrinfo* ai = 0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // check if error occurs when getting address info
    if (getaddrinfo("localhost", settings->portnum, &hints, &ai)) {
        char* portnum = strdup(settings->portnum);
        connection_error(portnum);
    }

    int fd = socket(AF_INET, SOCK_STREAM, DEFAULT_PROTOCOL);
    // check if error occurs when connecting t o port
    if (connect(fd, (struct sockaddr*)ai->ai_addr, sizeof(struct sockaddr))) {
        char* portnum = strdup(settings->portnum);
        connection_error(portnum);
    }

    // dup fd for reading and writing
    int fd2 = dup(fd);

    FILE* send = fdopen(fd, "w");

    // send name command
    fprintf(send, "name %s\n", settings->name);
    fflush(send);

    // send topic commands
    int topicCount = 0;
    while (settings->topics[topicCount]) {
        fprintf(send, "sub %s\n", settings->topics[topicCount]);
        fflush(send);
        topicCount++;
    }

    // Create thread to receive output from servers
    pthread_t tid;
    pthread_create(&tid, NULL, receive_server, &fd2);

    // read line from stdin and output to server until stdin EOF
    char* line = NULL;
    while ((line = read_line(stdin))) {
        fprintf(send, "%s\n", line);
        fflush(send);
        free(line);
    }
    exit(OK);
}

/**
 * receive_server()
 * 
 * Output to stdout any lines received from server. This occurs until
 * server EOF or other communication error
 * 
 * @param arg file descriptor of server
 * Errors: outputs error message to stderr and exits if server connection 
 * terminated
 */
void* receive_server(void* arg) {
    // cast file descriptor
    int fd = *((int *) arg);
    FILE* receive = fdopen(fd, "r");
    
    // read line from server and print until server EOF or communication error
    char* line = NULL;
    while ((line = read_line(receive))) {
        printf("%s\n", line);
        fflush(stdout);
        free(line);
    }
    fprintf(stderr, "psclient: server connection terminated\n");
    exit(SERVER_TERMINATED_ERROR);
}