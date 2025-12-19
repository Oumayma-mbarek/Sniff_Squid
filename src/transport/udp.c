#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <endian.h>


const unsigned char* parse_udp_header(const unsigned char* bytes,const unsigned char* end, int verbosity , uint16_t* src_port, uint16_t* dst_port)
{
    
    if((end - bytes) < sizeof(struct udphdr))
    {
        return NULL;
    }
    struct udphdr* udphdr = (struct udphdr*) bytes;
    if(verbosity==3)
    {
        printf("-------------- UDP ----------\n");
        printf("Source Port : %u\n", be16toh(udphdr->source));
        printf("Destination Port : %u\n",be16toh(udphdr->dest));
        printf("UDP Length : %u\n",be16toh(udphdr->len));
        printf("Checksum : %04x\n",be16toh(udphdr->check));
        printf("---------------------------\n");
    }
    else if(verbosity==2)
    {
        printf("UDP: Src port: %u, Dest port: %u\n", be16toh(udphdr->source),be16toh((udphdr->dest)));
    }
    else if(verbosity==1)
    {
        printf("UDP ");
    }

    *src_port= be16toh(udphdr->source);
    *dst_port= be16toh(udphdr->dest);
    return bytes+sizeof(struct udphdr);
}