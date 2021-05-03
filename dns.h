#include <stdio.h>
#include <stdlib.h>

#ifndef REFACTORED_OCTO_DNS_SERVER__DNS_H
#define REFACTORED_OCTO_DNS_SERVER__DNS_H

/*
* Masks and constants.
*/

static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x8000;
static const uint32_t RCODE_MASK = 0x000F;

/* Response Type */
enum {
    Ok_ResponseType = 0,
    FormatError_ResponseType = 1,
    ServerFailure_ResponseType = 2,
    NameError_ResponseType = 3,
    NotImplemented_ResponseType = 4,
    Refused_ResponseType = 5
};

/* Resource Record Types */
enum {
    A_Resource_RecordType = 1,
    NS_Resource_RecordType = 2,
    CNAME_Resource_RecordType = 5,
    SOA_Resource_RecordType = 6,
    PTR_Resource_RecordType = 12,
    MX_Resource_RecordType = 15,
    TXT_Resource_RecordType = 16,
    AAAA_Resource_RecordType = 28,
    SRV_Resource_RecordType = 33
};

/* Operation Code */
enum {
    QUERY_OperationCode = 0, /* standard query */
    IQUERY_OperationCode = 1, /* inverse query */
    STATUS_OperationCode = 2, /* server status request */
    NOTIFY_OperationCode = 4, /* request zone transfer */
    UPDATE_OperationCode = 5 /* change resource records */
};

/* Response Code */
enum {
    NoError_ResponseCode = 0,
    FormatError_ResponseCode = 1,
    ServerFailure_ResponseCode = 2,
    NameError_ResponseCode = 3
};

/* Query Type */
enum {
    IXFR_QueryType = 251,
    AXFR_QueryType = 252,
    MAILB_QueryType = 253,
    MAILA_QueryType = 254,
    STAR_QueryType = 255
};

/*
* Types.
*/

/* Question Section */
typedef struct question {
    char *qName;
    uint16_t qType;
    uint16_t qClass;
    struct question *next; // for linked list
}question_t;

/* Data part of a Resource Record */
typedef union resource_data {
    struct {
        uint8_t txt_data_len;
        char *txt_data;
    } txt_record;
    struct {
        uint8_t addr[4];
    } a_record;
    struct {
        uint8_t addr[16];
    } aaaa_record;
}resource_data_t;

/* Resource Record Section */
typedef struct resource_record {
    char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rd_length;
    resource_data_t rd_data;
    struct resource_record *next; // for linked list
}resource_record_t;

/*

0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

typedef struct message {
    uint16_t id; /* Identifier */
    /* Flags */
    union {
        struct {
            uint16_t qr:1;
            uint16_t Opcode:4;
            uint16_t aa:1;
            uint16_t tc:1;
            uint16_t rd:1;
            uint16_t ra:1;
            uint16_t z:1;
            uint16_t rcode:3;
        }u;
        uint16_t field;
    }byte;

    uint16_t qdCount; /* Question Count */
    uint16_t anCount; /* Answer Record Count */
    uint16_t nsCount; /* Authority Record Count */
    uint16_t arCount; /* Additional Record Count */

    /* At least one question; questions are copied to the response 1:1 */
    question_t *questions;

    /*
    * Resource records to be send back.
    * Every resource record can be in any of the following places.
    * But every place has a different semantic.
    */
    resource_record_t *answers;
    resource_record_t *authorities;
    resource_record_t *additionals;
}message_t;

int decode_dns_msg(message_t *msg, const uint8_t *buffer, uint32_t buffer_size);
void print_message(message_t *msg);

#endif //REFACTORED_OCTO_DNS_SERVER__DNS_H
