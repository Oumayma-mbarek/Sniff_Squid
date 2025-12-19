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
const unsigned char* parse_dns_name(
    const unsigned char* base,
    const unsigned char* ptr,
    const unsigned char* end,
    int depth);
const unsigned char* parse_rr(
    const unsigned char* base,
    const unsigned char* ptr,
    const unsigned char* end);

const unsigned char* parse_dns_header(const unsigned char* bytes,const unsigned char* end, int verbosity);
#endif 