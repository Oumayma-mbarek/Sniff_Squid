#ifndef IPV6_H
#define IPV6_H

#include <stdint.h>
const unsigned char* parse_ipv6_header(
    const unsigned char* bytes, const unsigned char* end, int verbosity, uint8_t* protocol
);

#endif
