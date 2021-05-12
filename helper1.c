#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "dns.h"
#include "helper1.h"

size_t
get16bits(const uint8_t **buffer)
{
    uint16_t value;

    memcpy(&value, *buffer, 2);
    *buffer += 2;
    return ntohs(value);
}

void
put8bits(uint8_t **buffer, uint8_t value)
{
    memcpy(*buffer, &value, 1);
    *buffer += 1;
}

void
put16bits(uint8_t **buffer, uint16_t value)
{
    value = htons(value);
    memcpy(*buffer, &value, 2);
    *buffer += 2;
}

void
put32bits(uint8_t **buffer, uint32_t value)
{
    value = htonl(value);
    memcpy(*buffer, &value, 4);
    *buffer += 4;
}

void updatefile_requested(int file_desc, char *domainName)
{
    time_t rawtime;
    struct tm *info;
    char buffer[80];

    time(&rawtime);

    info = localtime(&rawtime);
    strftime(buffer, 80, "%FT%T%z", info);
    dprintf(file_desc, "%s %s %s\n", buffer, "requested", domainName);
}

void updatefile_unimplemented_request(int file_desc)
{

    time_t rawtime;
    struct tm *info;
    char buffer[80];
    time(&rawtime);

    info = localtime(&rawtime);
    strftime(buffer, 80, "%FT%T%z", info);
    dprintf(file_desc, "%s %s\n", buffer, "unimplemented request");
}

void updatefile_ipaddress(int file_desc, message_t *parsed_dns_message)
{
    char str[INET6_ADDRSTRLEN];
    resource_record_t *temp = parsed_dns_message->answers;

    while (temp != NULL)
    {
        const char *string_ipv6 =
            inet_ntop(AF_INET6, temp->rd_data.aaaa_record.addr, str, INET6_ADDRSTRLEN);
        time_t rawtime;
        struct tm *info;
        char buffer[80];

        time(&rawtime);

        info = localtime(&rawtime);
        strftime(buffer, 80, "%FT%T%z", info);
        dprintf(file_desc, "%s %s is at %s\n", buffer, temp->name, string_ipv6);
        temp = temp->next;
    }
}
