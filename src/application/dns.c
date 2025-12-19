#include <arpa/inet.h>
#include <netinet/in.h>
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include "application/dns.h"

const unsigned char* parse_rr(
    const unsigned char* base,
    const unsigned char* ptr,
    const unsigned char* end)
{
    if (!ptr || ptr >= end)
        return NULL;

    /* NAME */
    printf("\t\tName: ");

    const unsigned char* p = parse_dns_name(base, ptr, end, 10);
    if (!p)
        return NULL;

    putchar('\n');

    ptr = p;

    /* TYPE + CLASS + TTL + RDLENGTH */
    if (ptr + 10 > end)
        return NULL;

    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;

    type = be16toh(*(uint16_t*) ptr);
    ptr+=2;
    
    class = be16toh(*(uint16_t*)ptr);
    ptr+=2;

    ttl=be32toh(*(uint32_t*)ptr);
    ptr+=4;

    rdlength = be16toh(*(uint16_t*) ptr);
    ptr += 2;

   
    printf("\t\tType: %u\n", type);
    printf("\t\tClass: %u\n", class);
    printf("\t\tTTL: %u\n", ttl);
    printf("\t\tRDLENGTH: %u\n", rdlength);
    

    /* RDATA */
    if (ptr + rdlength > end)
        return NULL;

    printf("\t\tRDATA:\n");
    for (int i = 0; i < rdlength; i++)
        printf("\t\t  %02x\n", ptr[i]);
    

    ptr += rdlength;
    return ptr;
}

const unsigned char* parse_dns_name(
    const unsigned char* base,
    const unsigned char* ptr,
    const unsigned char* end,
    int depth)
{
    if (!ptr || ptr >= end || depth <= 0)
        return NULL;

    const unsigned char* original_ptr = ptr;
    int jumped = 0;  // indique si on a suivi un pointeur

    while (ptr < end) {
        uint8_t len = *ptr;

        /* fin du nom */
        if (len == 0) {
            if (!jumped)
                ptr++;
            return jumped ? original_ptr + 2 : ptr;
        }

        /* pointeur DNS : 11xxxxxx */
        if ((len & 0xC0) == 0xC0) {
            if (ptr + 1 >= end)
                return NULL;

            uint16_t offset =
                ((len & 0x3F) << 8) | ptr[1];

            if (base + offset >= end)
                return NULL;

            /* afficher un point si nécessaire */
            putchar('.');

            ptr = base + offset;
            jumped = 1;
            depth--;
            continue;
        }

        /* label normal */
        if (len > 63 || ptr + 1 + len > end)
            return NULL;

        ptr++;

        for (int i = 0; i < len; i++)
            putchar(ptr[i]);

        ptr += len;

        if (*ptr != 0)
            putchar('.');
    }

    return NULL;
}



const unsigned char* parse_dns_header(const unsigned char* bytes,const unsigned char* end, int verbosity){
    if(bytes+sizeof(struct dnshdr)>end)
    {
        return NULL;
    }
    const struct dnshdr* dnshdr = (const struct dnshdr*) bytes;
    const unsigned char* p= bytes + sizeof(struct dnshdr);

    if(verbosity==3)
    {
        printf("----------- DNS -----------\n");
        printf("ID : %04x\n",be16toh(dnshdr->id));
        printf("Flags : \n");
        uint16_t flags= be16toh(dnshdr->flags);
        printf("\tQuery (0) or Response(1): %u\n",flags >> 15 );
        printf("\tOperation code %u\n",(flags >> 11 ) & 0xf);
        printf("\tAuthoritative Answer : %u\n",(flags>>10) & 0x1);
        printf("\tTruncation : %u\n",(flags>>9) & 0x1);
        printf("\tRecursion Desired %u\n",(flags>>8) & 0x1);
        printf("\tRecusion Available : %u\n",(flags>>7) & 0x1);
        printf("\tZ : %u\n",(flags>>4) &0x3);
        printf("\tResponse code  : %u\n",(flags)& 0x3);
        printf("Question Count : %u\n",be16toh(dnshdr->qdcount));
        printf("Answer Count : %u\n",be16toh(dnshdr->ancount));
        printf("NameServer Count : %u\n",be16toh(dnshdr->nscount));
        printf("Additional Records Count : %u\n",be16toh(dnshdr->arcount));
        uint16_t qdcount = be16toh(dnshdr->qdcount);
        uint16_t ancount = be16toh(dnshdr->ancount);
        uint16_t nscount = be16toh(dnshdr->nscount);
        uint16_t arcount = be16toh(dnshdr->arcount);

        for(int i = 0; i < qdcount; i++) {
            p = parse_dns_name(bytes, p, end, 10);
            uint16_t type_q = be16toh(*(uint16_t*)p); p += 2;
            uint16_t class_q = be16toh(*(uint16_t*)p); p += 2;

            printf("\tQuestion %d: type=%u class=%u\n", i+1, type_q, class_q);
        }

        for(int an=0;an<ancount;an++)
        {
            p = parse_rr(bytes,p,end);
        }
        for(int ns=0;ns<nscount;ns++)
        {
            p = parse_rr(bytes,p,end);
        }
        for(int ar=0;ar<arcount;ar++)
        {
            p = parse_rr(bytes,p,end);
        }

    }
    else if(verbosity==2)
    {
        printf("ID : %04x ,Question Count: %u , Answer count: %u,Nameserver Count: %u\n",be16toh(dnshdr->id),be16toh(dnshdr->qdcount),be16toh(dnshdr->ancount),be16toh(dnshdr->nscount));
    }
    else if (verbosity==1)
    {
        printf("DNS ");
    }

    return p ;

}
