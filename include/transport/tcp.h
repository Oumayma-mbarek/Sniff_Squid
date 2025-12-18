#ifndef TCP_H
#define TCP_H
#include <stdint.h>
const unsigned char* parse_tcp_header(const unsigned char* bytes, const unsigned char* end, int verbosity, uint16_t* src_port , uint16_t* dst_port );

#endif 