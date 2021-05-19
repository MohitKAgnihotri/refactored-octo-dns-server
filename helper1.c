#include <string.h>
#include <netinet/in.h>
#include "dns.h"
#include "helper1.h"

size_t get16bits(const uint8_t **buffer)
{
  uint16_t value;
  memcpy(&value, *buffer, 2);
  *buffer += 2;
  return ntohs(value);
}

void put16bits(uint8_t **buffer, uint16_t value)
{
  value = htons(value);
  memcpy(*buffer, &value, 2);
  *buffer += 2;
}

