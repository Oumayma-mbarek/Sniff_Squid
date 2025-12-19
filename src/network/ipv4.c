#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>

const unsigned char* parse_ipv4_header(const unsigned char* bytes, const unsigned char* end, int verbosity, uint8_t* protocol)
{
    if((end - bytes) < sizeof(struct ip))
    {
        return NULL;
    }
    struct ip* ip = (struct ip*)bytes;
    if(verbosity==3)
    {
        printf("---------------- IPV4 ------------------\n");
        char address[INET_ADDRSTRLEN];
        printf("version : %u\n", ip->ip_v);
        printf("Header length : %u\n", ip->ip_hl);
        printf("Type of Service : %u\n", ip->ip_tos);
        printf("total length : %u bytes\n", be16toh(ip->ip_len));
        printf("identifer : %u\n", be16toh(ip->ip_id));
        printf("reserved fragment flag : %u\n", ip->ip_off & IP_RF);
        printf("don't fragment flag : %u\n", ip->ip_off & IP_DF);
        printf("more fragments flag : %u\n", ip->ip_off & IP_MF);
        printf("fragment offset : %u\n", ip->ip_off & IP_OFFMASK);
        printf("Time to Live : %u\n", ip->ip_ttl);
        printf("Protocol : %u\n", ip->ip_p);
        printf("Checksum : %x\n", be16toh(ip->ip_sum));
        inet_ntop(AF_INET, &(ip->ip_src), address, INET_ADDRSTRLEN);
        printf("source address = %s\n", address);
        inet_ntop(AF_INET, &(ip->ip_dst), address, INET_ADDRSTRLEN);
        printf("destination address = %s\n", address);
        printf("------------------------------\n");
    }
    else if(verbosity==2)
    {
        char srcaddr[INET_ADDRSTRLEN];
        char dstaddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_src), srcaddr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->ip_dst), dstaddr, INET_ADDRSTRLEN);
        printf("IPV4: src addr:%s, dst addr: %s\n",srcaddr,dstaddr);
    }
    else if(verbosity==1)
    {
        printf("IPV4 ");
    }

    *protocol = ip->ip_p;
    return bytes + ip->ip_hl * 4;
}
