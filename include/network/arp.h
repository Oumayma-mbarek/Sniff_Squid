#ifndef ARP_H
#define ARP_H

const unsigned char* parse_arp_header(const unsigned char* bytes, const unsigned char* end, int verbosity);

#endif
