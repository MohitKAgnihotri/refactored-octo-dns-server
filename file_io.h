#include "dns.h"

#ifndef DNSSERVER__FILE_IO_H
#define DNSSERVER__FILE_IO_H

void file_io_init(char *file_name);
void file_io_log_cache_eviction(char *domainNameold, char *domainNameNew);
void file_io_init(char *file_name);
void file_io_log_ip_address(message_t *parsed_dns_message);
void file_io_update_unimplemented_request_type(void );
void file_io_update_domain_name(char *domainName);
void file_io_de_init();

#endif //DNSSERVER__FILE_IO_H
