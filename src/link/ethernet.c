#include <stdio.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <endian.h>

const unsigned char* parse_ethernet_header(
    const unsigned char* bytes, const unsigned char* end, int verbosity, uint16_t* ether_type
)
{
    if(bytes+ sizeof(struct ether_header)>end)
    {
        return NULL;
    }
    struct ether_header* eth = (struct ether_header*)bytes;
    *ether_type = be16toh(eth->ether_type);

    if(verbosity==3)
    {
        printf("--------Ethernet--------\n");
        char* address;
        address = ether_ntoa((struct ether_addr*)eth->ether_dhost);
        printf("destination: %s\n", address);
        address = ether_ntoa((struct ether_addr*)eth->ether_shost);
        printf("source: %s\n", address);
        printf("ether_type: 0x%04x\n", *ether_type);
        // TODO : add switch case to print ether type
        printf("--------------------------\n");

    }
    else if(verbosity==2)
    {
        printf("Ethernet ");
        char* srcaddr;
        char* dstaddr;
        dstaddr = ether_ntoa((struct ether_addr*)eth->ether_dhost);
        srcaddr = ether_ntoa((struct ether_addr*)eth->ether_shost);

        printf("Src: %s, Dst: %s\n",srcaddr,dstaddr);
    }
    else if(verbosity==1)
    {
        printf("Ethernet ");
    }
    return bytes + sizeof(struct ether_header);
}

