#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dns_cache.h"
#include "helper1.h"
#include "dns.h"

/* Function to decode domain name */
char *decode_domain_name(const uint8_t **buffer, int packet_size)
{
  char *domain_name_pointer = (char *) *buffer;
  char *domain_name = NULL;
  char *tmp_ptr = NULL;
  int name_part_len = 0;
  int dn_len = 0;

  do
  {
    /* Get the length of the next part of the domain name */
    name_part_len = (int) domain_name_pointer[0];

    /* If the length is zero or invalid, then stop processing the domain name */
    if ((name_part_len <= 0) || (name_part_len > (packet_size)))
    {
      break;
    }
    domain_name_pointer++;

    /* Reallocate domain_name pointer to name_part_len plus two bytes;
     * one byte for the period, and one more for the trailing NULL byte.
     */
    tmp_ptr = domain_name;
    domain_name = realloc(domain_name, (dn_len + name_part_len + 1 + 1));
    if (domain_name == NULL)
    {
      if (tmp_ptr)
        free(tmp_ptr);
      perror("Realloc Failure");
      return NULL;
    }
    memset(domain_name + dn_len, 0, name_part_len + 1 + 1);

    /* Concatenate this part of the domain name, plus the period */
    strncat(domain_name, domain_name_pointer, name_part_len);
    //strncat(domain_name,".",1);

    /* Keep track of how big domain_name is, and point
     * domain_name_pointer to the next part of the domain name.
     */
    dn_len += name_part_len + 1 + 1;
    domain_name_pointer += name_part_len;
    if (domain_name_pointer[0] > 0)
    {
      strncat(domain_name, ".", 1);
    }
  } while (name_part_len > 0);

  *buffer += (dn_len - 1);
  return domain_name;
}

/* Function to encode domain name */
void encode_domain_name(uint8_t **buffer, const char *domain)
{
  uint8_t *buf = *buffer;
  const char *beg = domain;
  const char *pos;
  int len = 0;
  int i = 0;

  while ((pos = strchr(beg, '.')))
  {
    len = pos - beg;
    buf[i] = len;
    i += 1;
    memcpy(buf + i, beg, len);
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

/* Function to decode DNS header */
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

/* Function to decode DNS message */
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

    if (q->qName == NULL)
    {
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
    memset(q, 0x00, sizeof(resource_record_t));
    q->name = strdup(msg->questions->qName);
    get16bits(&buffer);
    q->type = get16bits(&buffer);
    q->class = get16bits(&buffer);
    q->ttl = get16bits(&buffer) << 16 | get16bits(&buffer);
    if (dns_cache_isentry_exist(msg->questions->qName))
    {

    }
    q->rd_length = get16bits(&buffer);
    memcpy(&q->rd_data.aaaa_record, buffer, q->rd_length);
    buffer += q->rd_length;

    // prepend question to questions list
    if (msg->answers)
    {
      resource_record_t *curr = msg->answers;
      while (curr->next != NULL)
        curr = curr->next;
      curr->next = q;
      q->next = NULL;
    } else
    {
      msg->answers = q;
    }
  }
  return 0;
}

/* Encode the DNS header into the buffer */
void encode_header(message_t *msg, uint8_t **buffer)
{
  put16bits(buffer, msg->id);
  put16bits(buffer, msg->byte.field);
  put16bits(buffer, msg->qdCount);
  put16bits(buffer, msg->anCount);
  put16bits(buffer, msg->nsCount);
  put16bits(buffer, msg->arCount);
}

/* This function is used to encode the dns_structure in the buffer */
int encode_msg(message_t *msg, uint8_t **buffer)
{
  question_t *q;

  encode_header(msg, buffer);

  q = msg->questions;
  while (q)
  {
    encode_domain_name(buffer, q->qName);
    put16bits(buffer, q->qType);
    put16bits(buffer, q->qClass);
    q = q->next;
  }
  return 0;
}

/*Free resource allocated for the resource record */
void dns_free_resource_record(resource_record_t *record)
{
  resource_record_t *current_record = record;
  resource_record_t *temp = NULL;
  if (current_record != NULL)
  {
    free(current_record->name);
    temp = current_record;
    current_record = current_record->next;
    free(temp);
  }
}

/*Free resource allocated for the questions */
void dns_free_questions(question_t *question)
{
  question_t *current_question = question;
  question_t *temp = NULL;
  if (current_question != NULL)
  {
    free(current_question->qName);
    temp = current_question;
    current_question = current_question->next;
    free(temp);
  }
}

/* Free allocated messages and the resource */
void dns_free_message(message_t *msg)
{
  if (msg)
  {
    if (msg->questions)
    {
      dns_free_questions(msg->questions);
    }

    if (msg->answers)
    {
      dns_free_resource_record(msg->answers);
    }

    if (msg->additionals)
    {
      dns_free_resource_record(msg->additionals);
    }

    if (msg->authorities)
    {
      dns_free_resource_record(msg->authorities);
    }
  }
}

