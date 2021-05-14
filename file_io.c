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

void updatefile_requested(char *domainName)
{
  sem_wait(&sem_io);
  char buffer[80];
  FormatTime(buffer);
  dprintf(file_desp, "%s %s %s\n", buffer, "requested", domainName);
  sem_post(&sem_io);
}

void updatefile_unimplemented_request( void )
{
  sem_wait(&sem_io);
  char buffer[80];
  FormatTime(buffer);
  dprintf(file_desp, "%s %s\n", buffer, "unimplemented request");
  sem_post(&sem_io);
}

void updatefile_ipaddress(message_t *parsed_dns_message)
{
  sem_wait(&sem_io);
  char str[INET6_ADDRSTRLEN];
  resource_record_t *temp = parsed_dns_message->answers;

  while (temp != NULL)
  {
    const char *string_ipv6 =
        inet_ntop(AF_INET6, temp->rd_data.aaaa_record.addr, str, INET6_ADDRSTRLEN);

    char buffer[80];
    FormatTime(buffer);

    dprintf(file_desp, "%s %s is at %s\n", buffer, temp->name, string_ipv6);
    temp = temp->next;
  }
  sem_post(&sem_io);
}

void file_io_init(char *file_name)
{
  /*Setup the file pointer for the log file*/
  file_desp = open(file_name, O_WRONLY | O_APPEND | O_CREAT, 0644);
  sem_init(&sem_io, 0, 1);
}


void updatefile_eviction(char *domainNameold, char *domainNameNew)
{
  sem_wait(&sem_io);
  char buffer[80];
  FormatTime(buffer);
  dprintf(file_desp, "%s replacing %s by %s\n", buffer, domainNameold, domainNameNew);
  sem_post(&sem_io);
}

void file_io_de_init()
{
  close(file_desp);
}


