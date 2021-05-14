#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <semaphore.h>
#include <netdb.h>
#include "dns_cache.h"
#include "tick_timer.h"
#include "file_io.h"
#include "helper1.h"
#include "dns.h"

#define SOCKET_BUFF_SIZE 1500
#define BACKLOG 10
#define PORT_NUM 8053
#define TICK_TIMER_RESOLUTION 1 //sec

// enable NON-Blocking feature
#define NONBLOCKING 1
// enable cache feature
#define CACHE 1

int next_hierarchy_dns_server_port;
char *next_hierarchy_dns_server_name;

/* Thread routine to serve connection to client. */
void * pthread_routine(void *arg);

/* Signal handler to handle SIGTERM and SIGINT signals. */
void signal_handler_main(int signal_number);

void SetupSignalHandler();

int CreateServerSocket(int port);

int server_socket_fd;

int main(int argc, char *argv[])
{
  int port, new_socket_fd;
  pthread_attr_t pthread_client_attr;
  pthread_t pthread;
  socklen_t client_address_len;
  struct sockaddr_in client_address;

  if (argc < 3)
  {
    printf("Incorrect number of parameter \n");
    exit(0);
  }

  next_hierarchy_dns_server_name = argv[1];
  next_hierarchy_dns_server_port = atoi(argv[2]);

  /* Get port from command line arguments or stdin.
   * For this server, this is fixed to 1113*/
  port = PORT_NUM;

  /*Create the server socket */
  server_socket_fd = CreateServerSocket(port);

  /*Setup the signal handler*/
  SetupSignalHandler();

  /* Setup file operation f*/
  file_io_init("dns_svr.log");

  /*Setup Cache operation*/
  dns_cache_init();

  /*Setup the timer function*/
  tick_timer_init(TICK_TIMER_RESOLUTION, dns_cache_time_tick_handler);

  /* Initialise pthread attribute to create detached threads. */
  if (pthread_attr_init(&pthread_client_attr) != 0)
  {
    perror("pthread_attr_init");
    exit(1);
  }
  if (pthread_attr_setdetachstate(&pthread_client_attr, PTHREAD_CREATE_DETACHED) != 0)
  {
    perror("pthread_attr_setdetachstate");
    exit(1);
  }

  while (1)
  {

    /* Accept connection to client. */
    client_address_len = sizeof(client_address);
    new_socket_fd = accept(server_socket_fd, (struct sockaddr *) &client_address, &client_address_len);
    if (new_socket_fd == -1)
    {
      perror("accept");
      continue;
    }

    printf("Client connected\n");
    unsigned int *thread_arg = (unsigned int *) malloc(sizeof(unsigned int));
    *thread_arg = new_socket_fd;
    /* Create thread to serve connection to client. */
    if (pthread_create(&pthread, &pthread_client_attr, pthread_routine, (void *) thread_arg) != 0)
    {
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
  memset(&address, 0, sizeof(address));
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
  if (bind(socket_fd, (struct sockaddr *) &address, sizeof(address)) == -1)
  {
    perror("bind");
    exit(1);
  }

  /* Listen on socket. */
  if (listen(socket_fd, BACKLOG) == -1)
  {
    perror("listen");
    exit(1);
  }

  // Configure server socket
  int enable = 1;
  setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
  return socket_fd;
}

void SetupSignalHandler()
{
  /* Assign signal handlers to signals. */
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
  {
    perror("signal");
    exit(1);
  }
  if (signal(SIGTERM, signal_handler_main) == SIG_ERR)
  {
    perror("signal");
    exit(1);
  }
  if (signal(SIGINT, signal_handler_main) == SIG_ERR)
  {
    perror("signal");
    exit(1);
  }
}

int send_dns_request(int socket, char *server_name, uint8_t *buffer, int buffer_len)
{
  struct sockaddr_in servaddr;
  struct hostent *server_host;

  /* Get server host from server name. */
  server_host = gethostbyname(server_name);

  // Filling server information
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(next_hierarchy_dns_server_port);
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
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }
  return sockfd;
}

void *pthread_routine(void *arg)
{
  bool decrement_ttl;
  //Read from the client socket and print the received message on the screen
  uint8_t buffer[SOCKET_BUFF_SIZE] = {0};
  memset(buffer, 0x00, SOCKET_BUFF_SIZE);

  int client_socket = *(int *) arg;
  free(arg);

  message_t dns_request_msg_client;
  message_t dns_request_msg_upstream;

  /* Setup UDP client socket for upstream server */
  int upstream_server_sockfd = SetupUpstreamServerSocket(next_hierarchy_dns_server_name);

  // Read 2 bytes from the TCP socket
  unsigned short dns_request_length = 0;
  int bytes_read = read(client_socket, buffer, sizeof(dns_request_length));
  if (bytes_read > 0 && bytes_read == 2)
  {
    dns_request_length = buffer[0] << 16 | buffer[1];
    int len = 0;
    memset(buffer, 0x00, SOCKET_BUFF_SIZE);
    while (len != dns_request_length)
    {
      int readlen = read(client_socket, &buffer[len], dns_request_length);
      if (readlen > 0)
      {
        len += readlen;
      } else
      {
        perror("Failed to read from socked");
        exit(0);
      }
    }
  } else
  {
    exit(0);
  }


  memset(&dns_request_msg_client, 0x00, sizeof(dns_request_msg_client));
  decode_dns_msg(&dns_request_msg_client, buffer, dns_request_length);
  int incoming_request_id = dns_request_msg_client.id;

  // enter critical section
  // 1. Open file
  // 2. Write to the file.
  // 3. Close the file
  // Exit Critical section

  updatefile_requested(dns_request_msg_client.questions->qName);

  if (dns_cache_isentry_exist(dns_request_msg_client.questions->qName))
  {
    decrement_ttl = true;
  }
  if (dns_request_msg_client.questions->qType != AAAA_Resource_RecordType)
  {
    updatefile_unimplemented_request();
  }

  if (dns_request_msg_client.questions->qType == AAAA_Resource_RecordType)
  {
    // Check if the request can be served from local cache

    // send the DNS request to next level server
    send_dns_request(upstream_server_sockfd, next_hierarchy_dns_server_name, buffer, dns_request_length);

    // Wait for the response
    memset(buffer, 0x00, SOCKET_BUFF_SIZE);
    socklen_t len = 0;
    struct sockaddr_in servaddr;
    int bytes_received = recvfrom(upstream_server_sockfd,
                                  buffer,
                                  SOCKET_BUFF_SIZE,
                                  MSG_WAITALL,
                                  (struct sockaddr *) &servaddr,
                                  &len);
    if (bytes_received <= 0)
    {
      perror("error in recvfrom");
    }

    memset(&dns_request_msg_upstream, 0x00, sizeof(dns_request_msg_upstream));
    decode_dns_msg(&dns_request_msg_upstream, buffer, bytes_received);

    if (dns_request_msg_upstream.answers)
    {
      resource_record_t *temp = dns_request_msg_upstream.answers;
      while (temp != NULL)
      {
        dns_cache_add_entry(temp);
        temp = temp->next;
      }
    }

    if (dns_request_msg_upstream.byte.u.rcode == Ok_ResponseType && dns_request_msg_upstream.answers != NULL)
    {
      updatefile_ipaddress(&dns_request_msg_upstream);
    }

    // Send the response to the server
    uint8_t *response_msg = malloc(sizeof(char) * bytes_received + 2);
    uint8_t *resp_ptr = response_msg;
    memset(response_msg, 0x00, sizeof(char) * (bytes_received + 2));

    // add length
    put16bits(&response_msg, bytes_received);

    // add oroginal request
    put16bits(&response_msg, incoming_request_id);

    // copy the response received from the server
    memcpy(response_msg, &buffer[2], bytes_received - 2);

    int bytes_written = write(client_socket, resp_ptr, bytes_received + 2);
    if (bytes_written <= 0)
    {
      perror("error in write");
    }

    free(resp_ptr);

    // Update the cache
  }
  else
  {
    uint8_t *response_msg = malloc(1024);
    uint8_t *resp_ptr = response_msg + 2;

    // send Error Record for the Non-AAAA request
    message_t error_message;
    memset(&error_message, 0x00, sizeof(error_message));

    // set id
    error_message.id = incoming_request_id;

    // Set the type of message
    error_message.byte.u.qr = 1;
    error_message.byte.u.Opcode = 0;
    error_message.byte.u.aa = 0;
    error_message.byte.u.tc = 0;
    error_message.byte.u.rd = 0;
    error_message.byte.u.ra = 0;
    error_message.byte.u.z = 0;
    error_message.byte.u.rcode = NotImplemented_ResponseType;

    // leave most values intact for response
    error_message.qdCount = 0; /* Question Count */
    error_message.anCount = 0; /* Answer Record Count */
    error_message.nsCount = 0; /* Authority Record Count */
    error_message.arCount = 0; /* Additional Record Count */

    encode_msg(&error_message, &resp_ptr);
    int len = resp_ptr - response_msg - 2;
    resp_ptr = response_msg;
    put16bits(&resp_ptr, len);

    int bytes_written = write(client_socket, response_msg, sizeof(message_t) + 2);
    if (bytes_written <= 0)
    {
      perror("error in write");
    }
  }

  dns_free_message(&dns_request_msg_upstream);
  dns_free_message(&dns_request_msg_client);

  return NULL;
}

void signal_handler_main(int signal_number)
{

  printf("Caught SIGNINT");
  close(server_socket_fd);
  dns_cache_de_init();
  file_io_de_init();
  exit(0);
}
