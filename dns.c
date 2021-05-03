#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "helper1.h"
#include "dns.h"

#define MIN(x, y) ((x) <= (y) ? (x) : (y))

void print_resource_record(resource_record_t *rr)
{
    int i;
    while (rr) {
        printf("  ResourceRecord { name '%s', type %u, class %u, ttl %u, rd_length %u, ",
               rr->name,
               rr->type,
               rr->class,
               rr->ttl,
               rr->rd_length
        );

        resource_data_t *rd = &rr->rd_data;
        switch (rr->type) {
            case A_Resource_RecordType:
                printf("Address Resource Record { address ");

                for(i = 0; i < 4; ++i)
                    printf("%s%u", (i ? "." : ""), rd->a_record.addr[i]);

                printf(" }");
                break;
            case AAAA_Resource_RecordType:
                printf("AAAA Resource Record { address ");

                for(i = 0; i < 16; ++i)
                    printf("%s%02x", (i ? ":" : ""), rd->aaaa_record.addr[i]);

                printf(" }");
                break;
            case TXT_Resource_RecordType:
                printf("Text Resource Record { txt_data '%s' }",
                       rd->txt_record.txt_data
                );
                break;
            default:
                printf("Unknown Resource Record { ??? }");
        }
        printf("}\n");
        rr = rr->next;
    }
}

void print_message(message_t *msg)
{
    question_t *q;

    printf("QUERY { ID: %02x", msg->id);
    printf(". FIELDS: [ QR: %u, OpCode: %u ]", msg->byte.u.qr, msg->byte.u.Opcode);
    printf(", QDcount: %u", msg->qdCount);
    printf(", ANcount: %u", msg->anCount);
    printf(", NScount: %u", msg->nsCount);
    printf(", ARcount: %u,\n", msg->arCount);

    q = msg->questions;
    while (q) {
        printf("  Question { qName '%s', qType %u, qClass %u }\n",
               q->qName,
               q->qType,
               q->qClass
        );
        q = q->next;
    }

    print_resource_record(msg->answers);
    print_resource_record(msg->authorities);
    print_resource_record(msg->additionals);

    printf("}\n");
}

char *decode_domain_name(const uint8_t **buf, size_t len)
{
    char domain[256];
    for (int i = 1; i < MIN(256, len); i += 1) {
        uint8_t c = (*buf)[i];
        if (c == 0) {
            domain[i - 1] = 0;
            *buf += i + 1;
            return strdup(domain);
        } else if (c <= 63) {
            domain[i - 1] = '.';
        } else {
            domain[i - 1] = c;
        }
    }

    return NULL;
}

// foo.bar.com => 3foo3bar3com0
void encode_domain_name(uint8_t **buffer, const char *domain)
{
    uint8_t *buf = *buffer;
    const char *beg = domain;
    const char *pos;
    int len = 0;
    int i = 0;

    while ((pos = strchr(beg, '.'))) {
        len = pos - beg;
        buf[i] = len;
        i += 1;
        memcpy(buf+i, beg, len);
        i += len;

        beg = pos + 1;
    }

    len = strlen(domain) - (beg - domain);

    buf[i] = len;
    i += 1;

    memcpy(buf + i, beg, len);
    i += len;

    buf[i] = 0;
    i += 1;

    *buffer += i;
}

void decode_dns_header(message_t *msg, const uint8_t **buffer)
{
    assert(msg != NULL);
    assert(buffer != NULL);
    msg->id = get16bits(buffer);
    msg->byte.field = get16bits(buffer);

    msg->qdCount = get16bits(buffer);
    msg->anCount = get16bits(buffer);
    msg->nsCount = get16bits(buffer);
    msg->arCount = get16bits(buffer);
}

int decode_dns_msg(message_t *msg, const uint8_t *buffer, uint32_t buffer_size)
{

    assert(msg != NULL);
    assert(buffer != NULL);
    decode_dns_header(msg, &buffer);

    // parse questions
    for (int i = 0; i < msg->qdCount; ++i)
    {
        question_t *q = malloc(sizeof(question_t));
        q->qName = decode_domain_name(&buffer, buffer_size);
        q->qType = get16bits(&buffer);
        q->qClass = get16bits(&buffer);

        if (q->qName == NULL) {
            printf("Failed to decode domain name!\n");
            return -1;
        }

        // prepend question to questions list
        q->next = msg->questions;
        msg->questions = q;
    }
    return 0;
}

