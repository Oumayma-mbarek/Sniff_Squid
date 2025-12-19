#include <arpa/inet.h>
#include <netinet/in.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "application/dns.h"



const unsigned char* parse_dns_header(const unsigned char* bytes,const unsigned char* end, int verbosity){
    if(bytes+sizeof(struct dnshdr)>end)
    {
        return NULL;
    }
    const struct dnshdr* dnshdr = (const struct dnshdr*) bytes;
    if(verbosity==3)
    {
        printf("----------- DNS -----------\n");
        printf("ID : %04x\n",be16toh(dnshdr->id));
        printf("Flags : \n");
        uint16_t flags= dnshdr->flags;
        printf("Query (0) or Response(1): %u\n",flags >> 15 );
        printf("Operation code %u\n",(flags >> 11 ) & 0xf);
        printf("Authoritative Answer : %u\n",(flags>>10) & 0x1);
        printf("Truncation : %u\n",(flags>>9) & 0x1);
        printf("Recursion Desired %u\n",(flags>>8) & 0x1);
        printf("Recusion Available : %u\n",(flags>>7) & 0x1);
        printf("Z : %u\n",(flags>>4) &0x3);
        printf("Response code  : %u\n",(flags)& 0x3);
        printf("Question Count : %u\n",be16toh(dnshdr->qdcount));
        printf("Answer Count : %u\n",be16toh(dnshdr->ancount));
        printf("NameServer Count : %u\n",be16toh(dnshdr->nscount));
        printf("Additional Records Count : %u\n",be16toh(dnshdr->arcount));
    
        printf("------------------------\n");
    }
    else if(verbosity==2)
    {
        printf("ID : %04x ,Question Count: %u , Answer count: %u,Nameserver Count: %u\n",be16toh(dnshdr->id),be16toh(dnshdr->qdcount),be16toh(dnshdr->ancount),be16toh(dnshdr->nscount));
    }
    else if (verbosity==1)
    {
        printf(" ");
    }
    return end ;

}
