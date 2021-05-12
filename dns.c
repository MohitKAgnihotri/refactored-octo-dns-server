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

char *get_domain_in_question(const uint8_t **buffer, int packet_size)
{
    char *domain_name_pointer = (char*)*buffer;
    char *domain_name = NULL;
    char *tmp_ptr = NULL;
    int name_part_len = 0;
    int dn_len = 0;

    do {
        /* Get the length of the next part of the domain name */
        name_part_len = (int) domain_name_pointer[0];

        /* If the length is zero or invalid, then stop processing the domain name */
        if((name_part_len <= 0) || (name_part_len > (packet_size))){
            break;
        }
        domain_name_pointer++;

        /* Reallocate domain_name pointer to name_part_len plus two bytes;
         * one byte for the period, and one more for the trailing NULL byte.
         */
        tmp_ptr = domain_name;
        domain_name = realloc(domain_name,(dn_len+name_part_len+1+1));
        if(domain_name == NULL){
            if(tmp_ptr) free(tmp_ptr);
            perror("Realloc Failure");
            return NULL;
        }
        memset(domain_name+dn_len,0,name_part_len+1+1);

        /* Concatenate this part of the domain name, plus the period */
        strncat(domain_name,domain_name_pointer,name_part_len);
        //strncat(domain_name,".",1);

        /* Keep track of how big domain_name is, and point
         * domain_name_pointer to the next part of the domain name.
         */
        dn_len += name_part_len + 1 + 1;
        domain_name_pointer += name_part_len;
        if (domain_name_pointer[0] > 0)
        {
            strncat(domain_name,".",1);
        }
    } while(name_part_len > 0);

    *buffer += (dn_len-1);
    return domain_name;
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
        q->qName = get_domain_in_question(&buffer, buffer_size);
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

    // parse answers
    for (int i = 0; i < msg->anCount; ++i)
    {
        resource_record_t *q = malloc(sizeof(resource_record_t));
        q->name = strdup(msg->questions->qName);
        get16bits(&buffer);
        q->type = get16bits(&buffer);
        q->class = get16bits(&buffer);
        q->ttl =  get16bits(&buffer) << 16 | get16bits(&buffer);
        q->rd_length = get16bits(&buffer);
        memcpy(&q->rd_data.aaaa_record, buffer,q->rd_length);
        buffer += q->rd_length;

        // prepend question to questions list
        q->next = msg->answers;
        msg->answers = q;
    }
    return 0;
}

int encode_resource_records(resource_record_t *rr, uint8_t **buffer)
{
    int i;
    while (rr) {
        // Answer questions by attaching resource sections.
        encode_domain_name(buffer, rr->name);
        put16bits(buffer, rr->type);
        put16bits(buffer, rr->class);
        put32bits(buffer, rr->ttl);
        put16bits(buffer, rr->rd_length);

        switch (rr->type) {
            case A_Resource_RecordType:
                for(i = 0; i < 4; ++i)
                    put8bits(buffer, rr->rd_data.a_record.addr[i]);
                break;
            case AAAA_Resource_RecordType:
                for(i = 0; i < 16; ++i)
                    put8bits(buffer, rr->rd_data.aaaa_record.addr[i]);
                break;
            case TXT_Resource_RecordType:
                put8bits(buffer, rr->rd_data.txt_record.txt_data_len);
                for(i = 0; i < rr->rd_data.txt_record.txt_data_len; i++)
                    put8bits(buffer, rr->rd_data.txt_record.txt_data[i]);
                break;
            default:
                fprintf(stderr, "Unknown type %u. => Ignore resource record.\n", rr->type);
                return 1;
        }

        rr = rr->next;
    }

    return 0;
}


void encode_header(message_t *msg, uint8_t **buffer)
{
    put16bits(buffer, msg->id);
    put16bits(buffer, msg->byte.field);
    put16bits(buffer, msg->qdCount);
    put16bits(buffer, msg->anCount);
    put16bits(buffer, msg->nsCount);
    put16bits(buffer, msg->arCount);
}

int encode_msg(message_t *msg, uint8_t **buffer)
{
    question_t *q;
    int rc;

    encode_header(msg, buffer);

    q = msg->questions;
    while (q) {
        encode_domain_name(buffer, q->qName);
        put16bits(buffer, q->qType);
        put16bits(buffer, q->qClass);
        q = q->next;
    }

    rc = 0;
    rc |= encode_resource_records(msg->answers, buffer);
    rc |= encode_resource_records(msg->authorities, buffer);
    rc |= encode_resource_records(msg->additionals, buffer);

    return rc;
}

