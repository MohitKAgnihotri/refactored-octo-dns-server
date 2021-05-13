#include <semaphore.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "file_io.h"
#include "dns_cache.h"


#define MAX_DNS_CACHE_SIZE 5
sem_t sem_cache;

dns_cache_t dns_cache[MAX_DNS_CACHE_SIZE] = {0};

void dns_cache_init(void)
{
  sem_init(&sem_cache, 0, 1);
  memset(&dns_cache, 0x00, sizeof(dns_cache_t) * MAX_DNS_CACHE_SIZE);
}

void dns_cache_time_tick_handler(void)
{
  time_t current_time = time(NULL);
  sem_wait(&sem_cache);
  for (int i = 0; i < MAX_DNS_CACHE_SIZE; i++)
  {
    if (dns_cache[i].is_in_use && dns_cache[i].cached_dns_record.ttl < current_time)
    {
      dns_cache[i].is_in_use = false;
    }
  }
  sem_post(&sem_cache);
}

bool isRecordSame(resource_record_t *record_x, resource_record_t *record_y)
{
  assert(record_x != NULL);
  assert(record_y != NULL);

  bool is_domain_name_diff = strncmp(record_x->name, record_y->name, strlen(record_y->name));
  bool is_record_data_diff = memcmp(&record_x->rd_data, &record_y->rd_data, sizeof(resource_data_t));

  if (!is_domain_name_diff && !is_record_data_diff
      && (record_x->type == record_y->type)
      && (record_x->class == record_y->class)
      && (record_x->rd_length == record_y->rd_length))
  {
    return true;
  } else
  {
    return false;
  }
}

bool isRecordExist(resource_record_t *record, int *index)
{
  bool doesRecordExist = false;

  for (int i = 0; i < MAX_DNS_CACHE_SIZE; i++)
  {
    if (dns_cache[i].is_in_use && isRecordSame(&dns_cache[i].cached_dns_record, record))
    {
      doesRecordExist = true;
      *index = i;
      break;
    }
  }
  return doesRecordExist;
}

int dns_cache_find_entry_to_evict( void )
{
  uint32_t index = INT32_MAX;
  uint32_t min_ttl = INT32_MAX;

  for (int i = 0; i < MAX_DNS_CACHE_SIZE; i++)
  {
    if (dns_cache[i].is_in_use && min_ttl > dns_cache[i].cached_dns_record.ttl)
    {
      min_ttl = dns_cache[i].cached_dns_record.ttl;
      index = i;
    }
  }

  return index;

}

void dns_cache_add_entry(resource_record_t *record)
{
  int recordIndex;
  bool failed_to_insert = true;
  if (isRecordExist(record, &recordIndex))
  {
    if (recordIndex < MAX_DNS_CACHE_SIZE && recordIndex >= 0)
    {
      dns_cache[recordIndex].cached_dns_record.ttl = record->ttl + time(NULL);
      failed_to_insert = false;
    }
  } else
  {
    for(int i = 0; i < MAX_DNS_CACHE_SIZE; i++)
    {
      if (!dns_cache[i].is_in_use)
      {
        dns_cache[i].cached_dns_record.name = strdup(record->name);
        dns_cache[i].cached_dns_record.ttl = record->ttl + time(NULL);
        dns_cache[i].cached_dns_record.type = record->type;
        dns_cache[i].cached_dns_record.class = record->class;
        dns_cache[i].cached_dns_record.rd_length = record->rd_length;
        memcpy(&dns_cache[i].cached_dns_record.rd_data, &record->rd_data, record->rd_length);
        failed_to_insert = false;
        dns_cache[i].is_in_use = true;
        break;

      }
    }
  }

  if (!failed_to_insert)
  {
    uint32_t entry_to_evict = dns_cache_find_entry_to_evict();
    if (entry_to_evict < MAX_DNS_CACHE_SIZE && entry_to_evict >= 0)
    {
      updatefile_eviction(dns_cache[entry_to_evict].cached_dns_record.name, record->name);
      dns_cache[entry_to_evict].cached_dns_record.name = strdup(record->name);
      dns_cache[entry_to_evict].cached_dns_record.ttl = record->ttl + time(NULL);
      dns_cache[entry_to_evict].cached_dns_record.type = record->type;
      dns_cache[entry_to_evict].cached_dns_record.class = record->class;
      dns_cache[entry_to_evict].cached_dns_record.rd_length = record->rd_length;
      memcpy(&dns_cache[entry_to_evict].cached_dns_record.rd_data, &record->rd_data, record->rd_length);
    }
  }
}

void dns_cache_de_init( void )
{

}
