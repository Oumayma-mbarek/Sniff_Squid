#include <endian.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <stdio.h>


const unsigned char* parse_ipv6_header(const unsigned char* bytes, const unsigned char* end, int verbosity, uint8_t* protocol)
{
    if((end - bytes) < sizeof(struct ip6_hdr))
    {
        return NULL;
    }
    struct ip6_hdr* ip6 = (struct ip6_hdr*)bytes;
    char address[INET6_ADDRSTRLEN];
    uint32_t flow = be32toh(ip6->ip6_flow);
    printf("version : %u\n", flow >> 28);
    printf("traffic class : %u\n", (flow >> 20) & 0xFF);
    printf("flow label : %u\n", flow & 0xFFFFF);
    printf("Payload length : %u\n", be16toh(ip6->ip6_plen));
    printf("Next header : %u\n", ip6->ip6_nxt);
    printf("Hop Limit : %u\n", ip6->ip6_hlim);
    inet_ntop(AF_INET6, &(ip6->ip6_src), address, INET6_ADDRSTRLEN);
    printf("source address = %s\n", address);
    inet_ntop(AF_INET6, &(ip6->ip6_dst), address, INET6_ADDRSTRLEN);
    printf("destination address = %s\n", address);

    *protocol = ip6->ip6_nxt;
    return bytes + sizeof(struct ip6_hdr);
}
