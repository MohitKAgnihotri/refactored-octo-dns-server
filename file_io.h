#include "dns.h"

#ifndef DNSSERVER__FILE_IO_H
#define DNSSERVER__FILE_IO_H

void file_io_init(char *file_name);
void updatefile_eviction(char *domainNameold, char *domainNameNew);
void file_io_init(char *file_name);
void updatefile_ipaddress(message_t *parsed_dns_message);
void updatefile_unimplemented_request( void );
void updatefile_requested(char *domainName);


#endif //DNSSERVER__FILE_IO_H
