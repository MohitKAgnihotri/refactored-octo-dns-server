#include <stdbool.h>
#include "dns.h"

#ifndef DNSSERVER__DNS_CACHE_H
#define DNSSERVER__DNS_CACHE_H


typedef struct dns_cache
{
  bool is_in_use;
  resource_record_t cached_dns_record;
}dns_cache_t;

void dns_cache_time_tick_handler(void);
void dns_cache_init(void);
void dns_cache_add_entry(resource_record_t *record);
#endif //DNSSERVER__DNS_CACHE_H
