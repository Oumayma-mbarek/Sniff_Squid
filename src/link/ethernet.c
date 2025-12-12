#include <stdio.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <endian.h>

const unsigned char* parse_ethernet_header(
    const unsigned char* bytes, const unsigned char* end, int verbosity, uint16_t* ether_type
)
{
    if((end - bytes) < sizeof(struct ether_header))
    {
        return NULL;
    }
    struct ether_header* eth = (struct ether_header*)bytes;

    char* address;
    address = ether_ntoa((struct ether_addr*)eth->ether_dhost);
    printf("destination: %s\n", address);
    address = ether_ntoa((struct ether_addr*)eth->ether_shost);
    printf("source: %s\n", address);
    *ether_type = be16toh(eth->ether_type);
    printf("ether_type: 0x%04x\n", *ether_type);
    // TODO : add switch case to print ether type
    return bytes + sizeof(struct ether_header);
}

