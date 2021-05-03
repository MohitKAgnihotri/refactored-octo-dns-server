#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <semaphore.h>
#include <netdb.h>
#include "helper1.h"
#include "dns.h"

#define SOCKET_BUFF_SIZE 1500
#define BACKLOG 10
#define PORT_NUM 8053


/* Thread routine to serve connection to client. */
void *pthread_routine(void *arg);

/* Signal handler to handle SIGTERM and SIGINT signals. */
void signal_handler(int signal_number);

void SetupSignalHandler();

int CreateServerSocket(int port);

int server_socket_fd;

// Semaphore of the File access
sem_t sem_io;

FILE *fp = NULL;

int main(int argc, char *argv[])
{
    int port, new_socket_fd;
    pthread_attr_t pthread_client_attr;
    pthread_t pthread;
    socklen_t client_address_len;
    struct sockaddr_in client_address;

    /* Get port from command line arguments or stdin.
     * For this server, this is fixed to 1113*/
    port = PORT_NUM;

    /*Create the server socket */
    server_socket_fd = CreateServerSocket(port);

    /*Setup the signal handler*/
    SetupSignalHandler();

    /* Setup the semaphore of IO*/
    sem_init(&sem_io,0,1);

    /*Setup the file pointer for the log file*/
    fp = fopen("./dns_svr.log","wb");

    /* Initialise pthread attribute to create detached threads. */
    if (pthread_attr_init(&pthread_client_attr) != 0) {
        perror("pthread_attr_init");
        exit(1);
    }
    if (pthread_attr_setdetachstate(&pthread_client_attr, PTHREAD_CREATE_DETACHED) != 0) {
        perror("pthread_attr_setdetachstate");
        exit(1);
    }

    while (1) {

        /* Accept connection to client. */
        client_address_len = sizeof (client_address);
        new_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_address, &client_address_len);
        if (new_socket_fd == -1) {
            perror("accept");
            continue;
        }

        printf("Client connected\n");
        unsigned int *thread_arg = (unsigned int *) malloc(sizeof(unsigned int));
        *thread_arg = new_socket_fd;
        /* Create thread to serve connection to client. */
        if (pthread_create(&pthread, &pthread_client_attr, pthread_routine, (void *)thread_arg) != 0) {
            perror("pthread_create");
            continue;
        }
    }

    return 0;
}


int CreateServerSocket(int port)
{
    struct sockaddr_in address;
    int socket_fd;

    /* Initialise IPv4 address. */
    memset(&address, 0, sizeof (address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = INADDR_ANY;

    /* Create TCP socket. */
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        exit(1);
    }

    /* Bind address to socket. */
    if (bind(socket_fd, (struct sockaddr *)&address, sizeof (address)) == -1) {
        perror("bind");
        exit(1);
    }

    /* Listen on socket. */
    if (listen(socket_fd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    // Configure server socket
    int enable = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    return socket_fd;
}

void SetupSignalHandler() {/* Assign signal handlers to signals. */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal");
        exit(1);
    }
    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        perror("signal");
        exit(1);
    }
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        perror("signal");
        exit(1);
    }
}

int send_dns_request(int socket, char *server_name, uint8_t *buffer, int buffer_len)
{
    struct sockaddr_in     servaddr;
    struct hostent *server_host;

    /* Get server host from server name. */
    server_host = gethostbyname(server_name);

    // Filling server information
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(53);
    memcpy(&servaddr.sin_addr.s_addr, server_host->h_addr, server_host->h_length);

    int bytes_sent = sendto(socket, buffer, buffer_len,
                            0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
    if (bytes_sent <= 0)
    {
        perror("sendto");
        return -1;
    }
    return 0;
}


int SetupUpstreamServerSocket(char *servername)
{
    int sockfd;
    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

void *pthread_routine(void *arg)
{
    //Read from the client socket and print the received message on the screen
    uint8_t buffer[SOCKET_BUFF_SIZE] = {0};
    memset(buffer, 0x00, SOCKET_BUFF_SIZE);

    int client_socket = *(int*) arg;
    free(arg);

    /* Setup UDP client socket for upstream server */
    int upstream_server_sockfd = SetupUpstreamServerSocket("8.8.8.8");

    int bytes_read = read(client_socket, buffer, SOCKET_BUFF_SIZE);
    if (bytes_read > 0)
    {
        message_t dns_request_msg;
        memset(&dns_request_msg, 0x00, sizeof(dns_request_msg));

        int dns_request_length = buffer[0] << 16 | buffer[1];

        decode_dns_msg( &dns_request_msg, &buffer[2], dns_request_length);
        int incoming_request_id = dns_request_msg.id;
        print_message(&dns_request_msg);

        // enter critical section
        // 1. Open file
        // 2. Write to the file.
        // 3. Close the file
        // Exit Critical section
        sem_wait(&sem_io);
        updatefile(fp,dns_request_msg.questions->qName);
        sem_post(&sem_io);

        // Check if the request can be served from local cache

        // send the DNS request to next level server
        send_dns_request(upstream_server_sockfd, "8.8.8.8", &buffer[2], dns_request_length);

        // Wait for the response
        memset(buffer, 0x00, SOCKET_BUFF_SIZE);
        socklen_t len;
        struct sockaddr_in     servaddr;
        int bytes_received = recvfrom(upstream_server_sockfd, buffer, SOCKET_BUFF_SIZE,MSG_WAITALL, (struct sockaddr *) &servaddr, &len);
        if (bytes_received <= 0)
        {
            perror("error in recvfrom");
        }

        // Send the response to the server
        uint8_t *response_msg = malloc(sizeof(char) * bytes_received + 2);
        uint8_t *resp_ptr = response_msg;
        memset(response_msg, 0x00, sizeof(char) * (bytes_received + 2));

        // add length
        put16bits(&response_msg,bytes_received);

        // add oroginal request
        put16bits(&response_msg,incoming_request_id);

        // copy the response received from the server
        memcpy(response_msg, &buffer[2], bytes_received-2);

        int bytes_written = write(client_socket,resp_ptr,bytes_received+2);
        if (bytes_written <= 0)
        {
            perror("error in write");
        }

        // Update the cache


    }
    else if (bytes_read  == 0)
    {
        // socket closed from the client.
    }
    else
    {
        perror("socket read error \n");
    }

    return NULL;
}

void signal_handler(int signal_number)
{
    close(server_socket_fd);
    fclose(fp);
    exit(0);
}
