#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>

const unsigned char* parse_ipv4_header(
    const unsigned char* bytes, const unsigned char* end, int verbosity, uint8_t* protocol
);

#endif
