#include <endian.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdio.h>

const unsigned char* parse_arp_header(const unsigned char* bytes, const unsigned char* end, int verbosity)
{
    if((end - bytes) < sizeof(struct arphdr))
    {
        return NULL;
    }
    struct arphdr* arphdr = (struct arphdr*)bytes;
    if (verbosity==3)
    {
        printf("-------------- ARP ---------------\n");
        char* hardware_address;
        char protocol_address[INET_ADDRSTRLEN];
        printf("Hardware type : %u\n", be16toh(arphdr->ar_hrd));
        printf("Protocol type : %u\n", be16toh(arphdr->ar_pro));
        printf("Hardware length : %u\n", arphdr->ar_hln);
        printf("Protocol length : %u\n", arphdr->ar_pln);
        printf("Operation : %u\n", be16toh(arphdr->ar_op));
        if(be16toh((arphdr->ar_hrd) == 1))
        {
            hardware_address = ether_ntoa((struct ether_addr*)(bytes + sizeof(struct arphdr)));
            printf("Sender Hardware Address : %s\n", hardware_address);
            hardware_address =
                ether_ntoa((struct ether_addr*)(bytes + sizeof(struct arphdr) + arphdr->ar_hln + arphdr->ar_pln));
            printf("Target Hardware Address : %s\n", hardware_address);
        }
        if(be16toh((arphdr->ar_pro) == 0x800))
        {
            inet_ntop(AF_INET, (bytes + sizeof(struct arphdr) + arphdr->ar_hln), protocol_address, INET_ADDRSTRLEN);
            printf("Sender Protocol Address  = %s\n", protocol_address);
            inet_ntop(AF_INET, (bytes + sizeof(struct arphdr) + 2 * arphdr->ar_hln + arphdr->ar_pln), protocol_address, INET_ADDRSTRLEN);
            printf("Target Protocol Address  = %s\n", protocol_address);
        }
        printf("----------------------------------\n");
    }
    else if(verbosity==2)
    {
        char* shaddr;
        char* thaddr;
        shaddr = ether_ntoa((struct ether_addr*)(bytes + sizeof(struct arphdr)));
        thaddr = ether_ntoa((struct ether_addr*)(bytes + sizeof(struct arphdr)+ arphdr->ar_hln + arphdr->ar_pln));
        printf("Sender hardware addr: %s, Target hardware addr: %s\n",shaddr,thaddr);
    }
    else if(verbosity==1)
    {
        printf("ARP ");
    }
    return 0;
}
