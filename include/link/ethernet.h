#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>
const unsigned char* parse_ethernet_header(
    const unsigned char* bytes, const unsigned char* end, int verbosity, uint16_t* ether_type
);

#endif
