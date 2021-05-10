#include "dns.h"

size_t get16bits(const uint8_t **buffer);
void put8bits(uint8_t **buffer, uint8_t value);
void put16bits(uint8_t **buffer, uint16_t value);
void put32bits(uint8_t **buffer, uint32_t value);
void updatefile_unimplemented_request(FILE *fp);
void updatefile_requested(FILE *fp, char *domainName);
void updatefile_ipaddress(FILE *fp, message_t *parsed_dns_message);

