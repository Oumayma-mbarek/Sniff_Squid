#ifndef DNS_H
#define DNS_H
#include <stdint.h>

struct dnshdr
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

};
const unsigned char* parse_dns_header(const unsigned char* bytes,const unsigned char* end, int verbosity);
#endif 