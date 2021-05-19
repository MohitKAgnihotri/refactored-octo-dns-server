#include <time.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <semaphore.h>
#include <unistd.h>
#include "dns.h"
#include "file_io.h"

int file_desp;
sem_t sem_io;

void FormatTime(char *buffer)
{
  time_t rawtime;
  struct tm *info;
  time(&rawtime);
  info = localtime(&rawtime);
  strftime(buffer, 80, "%FT%T%z", info);
}

/* Function is used to write domain name for which request is received */
void file_io_update_domain_name(char *domainName)
{
  sem_wait(&sem_io);
  char buffer[80];
  FormatTime(buffer);
  dprintf(file_desp, "%s %s %s\n", buffer, "requested", domainName);
  sem_post(&sem_io);
}

/* Function is used to log un-supported request */
void file_io_update_unimplemented_request_type(void )
{
  sem_wait(&sem_io);
  char buffer[80];
  FormatTime(buffer);
  dprintf(file_desp, "%s %s\n", buffer, "unimplemented request");
  sem_post(&sem_io);
}

/* Function is used to write log IP address */
void file_io_log_ip_address(message_t *parsed_dns_message)
{
  sem_wait(&sem_io);
  if (parsed_dns_message && parsed_dns_message->answers->type == AAAA_Resource_RecordType)
  {
    char str[INET6_ADDRSTRLEN];

    const char *string_ipv6 =
        inet_ntop(AF_INET6, parsed_dns_message->answers->rd_data.aaaa_record.addr, str, INET6_ADDRSTRLEN);

    char buffer[80];
    FormatTime(buffer);

    dprintf(file_desp, "%s %s is at %s\n", buffer, parsed_dns_message->answers->name, string_ipv6);
  }
  sem_post(&sem_io);
}

void file_io_init(char *file_name)
{
  /*Setup the file pointer for the log file*/
  file_desp = open(file_name, O_WRONLY | O_APPEND | O_CREAT, 0644);
  sem_init(&sem_io, 0, 1);
}

/* Function is used to log cache eviction event */
void file_io_log_cache_eviction(char *domainNameold, char *domainNameNew)
{
  sem_wait(&sem_io);
  char buffer[80];
  FormatTime(buffer);
  dprintf(file_desp, "%s replacing %s by %s\n", buffer, domainNameold, domainNameNew);
  sem_post(&sem_io);
}

/*Close the file descriptor. */
void file_io_de_init()
{
  close(file_desp);
}


