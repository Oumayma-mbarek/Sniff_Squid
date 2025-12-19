#include <endian.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>




const unsigned char* parse_tcp_header(const unsigned char* bytes, const unsigned char* end, int verbosity, uint16_t* src_port , uint16_t* dst_port )
{
    if(bytes+sizeof(struct tcphdr)>end)
    {
        return NULL;
    }
    struct tcphdr* tcphdr = (struct tcphdr* ) bytes;
    if(verbosity==3)
    {
        printf("--------------- TCP -------------\n ");
        printf("Source Port : %u\n", be16toh(tcphdr->source));
        printf("Destination Port : %u\n",be16toh(tcphdr->dest));
        printf("Sequence Number : %u\n",be32toh(tcphdr->seq));
        printf("Acknowledgment Number : %u\n", be32toh(tcphdr->ack_seq));
        printf("Data offset : %u\n",tcphdr->doff);
        printf("Urgent Flag : %u\n",tcphdr->urg);
        printf("Ack Flag : %u\n",tcphdr->ack);
        printf("Push Flag : %u\n",tcphdr->psh);
        printf("Reset Flag : %u\n",tcphdr->rst);
        printf("SYN Flag : %u\n",tcphdr->syn);
        printf("FIN Flag : %u\n",tcphdr->fin);
        printf("Window : %u\n",be16toh(tcphdr->window));
        printf("Checksum : %04x\n",be16toh(tcphdr->check));
        printf("Urgent Pointer : %u\n",be16toh(tcphdr->urg_ptr));
        printf("----------------------------\n");
    }
    else if(verbosity==2)
    {
        printf("TCP: src port: %u, dst port: %u\n",be16toh(tcphdr->source),be16toh(tcphdr->dest));
    }
    else if(verbosity==1)
    {
        printf("TCP ");
    }
    *src_port = be16toh(tcphdr->source);
    *dst_port = be16toh(tcphdr->dest);
    return bytes + tcphdr->doff * 4 ; 
}