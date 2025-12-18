#ifndef TELNET_H
#define TELNET_H
#include <stdio.h>

ssize_t parse_telnet_options(const unsigned char* bytes, const unsigned char* end , ssize_t offset);
ssize_t parse_special_command(const unsigned char* bytes, const unsigned char* end,ssize_t offset);
const unsigned char* parse_telnet(const unsigned char* bytes,const unsigned char* end, int verbosity);
#endif