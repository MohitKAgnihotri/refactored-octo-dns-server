#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "dns.h"
#include "helper1.h"

size_t get16bits(const uint8_t **buffer)
{
    uint16_t value;

    memcpy(&value, *buffer, 2);
    *buffer += 2;
    return ntohs(value);
}

void put8bits(uint8_t **buffer, uint8_t value)
{
    memcpy(*buffer, &value, 1);
    *buffer += 1;
}

void put16bits(uint8_t **buffer, uint16_t value)
{
    value = htons(value);
    memcpy(*buffer, &value, 2);
    *buffer += 2;
}

void put32bits(uint8_t **buffer, uint32_t value)
{
    value = htonl(value);
    memcpy(*buffer, &value, 4);
    *buffer += 4;
}

void updatefile_requested(FILE *fp, char *domainName)
{
    if (fp)
    {
        time_t rawtime;
        struct tm *info;
        char buffer[80];

        time(&rawtime);

        info = localtime(&rawtime);
        strftime(buffer, 80, "%FT%T%z", info);
        fprintf(fp, "%s %s %s\n", buffer, "requested", domainName);
        fflush(fp);
    }
}

void updatefile_unimplemented_request(FILE *fp)
{
    if (fp)
    {
        time_t rawtime;
        struct tm *info;
        char buffer[80];

        time(&rawtime);

        info = localtime(&rawtime);
        strftime(buffer, 80, "%FT%T%z", info);
        fprintf(fp, "%s %s\n", buffer, "unimplemented request");
        fflush(fp);
    }
}

void updatefile_ipaddress(FILE *fp, message_t *parsed_dns_message)
{
    if (fp)
    {
        char str[INET6_ADDRSTRLEN];
        const char * string_ipv6 = inet_ntop(AF_INET6, parsed_dns_message->answers->rd_data.aaaa_record.addr, str, INET6_ADDRSTRLEN);
        time_t rawtime;
        struct tm *info;
        char buffer[80];

        time(&rawtime);

        info = localtime(&rawtime);
        strftime(buffer, 80, "%FT%T%z", info);
        fprintf(fp, "%s %s  is at  %s\n", buffer, parsed_dns_message->answers->name, string_ipv6);
        fflush(fp);
    }
}
