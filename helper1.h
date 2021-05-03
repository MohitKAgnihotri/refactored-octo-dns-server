

size_t get16bits(const uint8_t **buffer);
void put8bits(uint8_t **buffer, uint8_t value);
void put16bits(uint8_t **buffer, uint16_t value);
void put32bits(uint8_t **buffer, uint32_t value);
void updatefile(FILE*fp, char *domainName);

