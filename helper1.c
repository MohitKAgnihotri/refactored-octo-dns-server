#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>
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


void updatefile(FILE*fp, char *domainName)
{
    if (fp)
    {
        time_t rawtime;
        struct tm *info;
        char buffer[80];

        time( &rawtime );

        info = localtime( &rawtime );
        strftime(buffer,80,"%FT%T%z", info);
        if (domainName)
        {
            fprintf(fp,"%s %s %s\n",buffer, "requested", domainName);
        }
        else
        {
            fprintf(fp,"%s %s\n",buffer, "unimplemented request");
        }
        fflush(fp);
    }
}
