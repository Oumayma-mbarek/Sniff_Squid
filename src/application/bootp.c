#include "application/bootp.h"
#include <arpa/inet.h>
#include <endian.h>
#include <stdio.h> 
#include <netinet/ether.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

static const char* dhcp_message_type[] = {
    "DISCOVER" ,
    "OFFER" ,
    "REQUEST" ,
    "DECLINE" ,
    "ACK" ,
    "NACK" ,
    "RELEASE" ,
    "INFORM" ,
    "FORCE_RENEW" ,
    "LEASE_QUERY" ,
    "LEASE_UNASSIGNED" ,
    "LEASE_UNKNOWN" ,
    "LEASE_ACTIVE" ,
    "BULK_LEASE_QUERY" ,
    "LEASE_QUERY_DONE" ,
    "ACTIVE_LEASE_QUERY" ,
    "LEASE_QUERY_STATUS" ,
    "TLS" 
};
static void print_dhcp_tlv_type(uint8_t type)
{
    switch(type)
    {
        case DHCP_SUBNET_MASK:
            printf(" (Subnet Mask)\n");
            break;
        case DHCP_ROUTER:
            printf(" (Router)\n");
            break;
        case DHCP_DOMAIN_NAME_SERVER:
            printf(" (Domain Name Server)\n");
            break;
        case DHCP_HOSTNAME:
            printf(" (Hostname)\n");
            break;
        case DHCP_DOMAIN_NAME:
            printf(" (Domain Name)\n");
            break;
        case DHCP_NTP_SERVERS:
            printf(" (NTP Servers Addresses)\n");
            break;
        case DHCP_ADDRESS_REQUEST:
            printf(" (Requested IP Address)\n");
            break;
        case DHCP_LEASE_TIME:
            printf(" (IP Address Lease Time)\n");
            break;
        case DHCP_MESSAGE_TYPE:
            printf(" (Message Type)\n");
            break;
        case DHCP_SERVER_ID:
            printf(" (Server Identifier)\n");
            break;
        case DHCP_RENEWAL:
            printf(" (Renewal Time)\n");
            break;
        case DHCP_REBINDING:
            printf(" (Rebinding Time)\n");
            break;
        case DHCP_PARAMETER_REQUEST_LIST:
            printf(" (Parameter Request List)\n");
            break;
        case DHCP_CLIENT_ID:
            printf(" (Client Identifier)\n");
            break;
    }
}
void parse_dhcp_tlv(const unsigned char* bytes, const unsigned char* end)
{
    printf("Magic Cookie : 0x%08x\n",be32toh(*((uint32_t*)bytes)));
    bytes+=4;
    while(bytes<end)
    {
        if(bytes + sizeof(uint8_t) >end)
        {
            return;
        }
        uint8_t type = *bytes;
        bytes++;

        if(type== DHCP_END)
        {

        }
        if(type== DHCP_NOP)
        {
            continue;
        }
        if(bytes+sizeof(uint8_t)>end)
        {
            return;
        }
        uint8_t length= *bytes;
        bytes++;
        if(bytes+length>end)
        {
            return ;
        }
        printf("Type: %d\n",type);
        print_dhcp_tlv_type(type);
        printf("Length : %d\n",length);
        printf("Value : ");
        switch(type)
        {
            char buffer[INET_ADDRSTRLEN];
            case DHCP_SUBNET_MASK:
            case DHCP_ADDRESS_REQUEST:
            case DHCP_SERVER_ID:
                printf(" %s\n", inet_ntop(AF_INET, bytes, buffer, INET_ADDRSTRLEN));
                break;
            case DHCP_ROUTER :
            case DHCP_DOMAIN_NAME_SERVER:
            case DHCP_NTP_SERVERS:
                putchar('\n');
                for(int i = 0; i < length; i += 4)
                {
                    printf("\t\t\t%s\n", inet_ntop(AF_INET, bytes + i, buffer, INET_ADDRSTRLEN));
                }
                break;
            case DHCP_HOSTNAME:
            case DHCP_DOMAIN_NAME:
                for(int i=0;i<length;i++)
                {
                    printf("%c",bytes[i]);
                } 
                printf("\n");
                break;
            case DHCP_LEASE_TIME:
            case DHCP_RENEWAL:
            case DHCP_REBINDING:
                printf(" %u seconds\n", be32toh(*((uint32_t*)bytes)));
                break;

            case DHCP_MESSAGE_TYPE:
                {
                    uint8_t message_type = *bytes;
                    printf(" %d (%s)\n", *bytes, dhcp_message_type[message_type]);
                }
                break;
            case DHCP_PARAMETER_REQUEST_LIST:
                putchar('\n');
                for(int i = 0; i < length; i++)
                {
                    printf("\t\t\t%d", bytes[i]);
                    print_dhcp_tlv_type(bytes[i]);
                    putchar('\n');
                }
                break;
            case DHCP_CLIENT_ID:
                printf("\tHardware Address Type: %d\n", *bytes);
                printf("\ttHardware Address: ");
                ether_ntoa((struct ether_addr*)&(bytes));
                putchar('\n');
                break;

            default:
                putchar('\n');
                for (int i=0 ; i<length; i++)
                {
                    putchar(bytes[i]);
                }
                putchar('\n');
        }
        putchar('\n');
        bytes+=length;
    }
    return;
}
const unsigned char* parse_bootp_header(const unsigned char* bytes, const unsigned char* end, int verbosity)
{
    if( bytes + sizeof(struct bootphdr) > end)
    {
        return NULL;
    }
    bool dhcp = false;
    struct bootphdr* bootphdr = (struct bootphdr* ) bytes;
    uint8_t dhcp_cookie[4] = {0x63, 0x82, 0x53, 0x63};
    if (memcmp(bootphdr->vend, dhcp_cookie, 4) == 0)   
    {
        dhcp = true;
    }
    if(verbosity==3)
    {
        if(dhcp)
        {
            printf("------------ DHCP -------------\n");
        }
        else 
        {
            printf("---------- BOOTP -----------\n");
        }
        char address[INET_ADDRSTRLEN];
        char* hardware_address;
    
        printf("Operation Code (1:Request, 2:Reply): %u\n",bootphdr->op);
        printf("Hardware address type : %u\n",bootphdr->htype);
        printf("Hardware address length : %u\n",bootphdr->hlen);
        printf("Hop count : %u\n",bootphdr->hops);
        printf("Transaction ID : %08x\n",be32toh(bootphdr->xid));
        printf("Seconds : %u\n",be16toh(bootphdr->secs));
        printf("Flags : %u\n",bootphdr->flags);
        inet_ntop(AF_INET, &(bootphdr->ciaddr), address, INET_ADDRSTRLEN);
        printf("Client IP address = %s\n", address);    
        inet_ntop(AF_INET, &(bootphdr->yiaddr), address, INET_ADDRSTRLEN);
        printf("Your IP address = %s\n", address);
        inet_ntop(AF_INET, &(bootphdr->siaddr), address, INET_ADDRSTRLEN);
        printf("Server IP address = %s\n", address);
        inet_ntop(AF_INET, &(bootphdr->giaddr), address, INET_ADDRSTRLEN);
        printf("Gateway IP address = %s\n", address);
        if(bootphdr->htype==1)
        {
            hardware_address = ether_ntoa((struct ether_addr*)&(bootphdr->chaddr));
            printf("Client Hardware Address : %s\n", hardware_address);
        }
        printf("Server Hostname : %s\n", bootphdr->sname);
        printf("File : %s\n", bootphdr->file);
        printf("\t\tVendor :\n");
        if(dhcp)
        {
            parse_dhcp_tlv( bootphdr->vend, end);
        }
        else 
        {   
            if(bootphdr->vend + 64 > end)
            {
                return NULL;
            }
            for (int i=0;i<64;i++)
            {
                printf("%02x ",bootphdr->vend[i]);
            }
        }
        
        printf("\n");
    }
    else if(verbosity==2)
    {
        if(dhcp)
        {
            printf("DHCP:  ");
            printf("Operation code: %u\n",bootphdr->op);
        }
        else 
        {
            printf("BOOTP");
            printf("Operation code: %u\n",bootphdr->op);
        }
    }
    else if(verbosity==1)
    {
        if(dhcp)
        {
            printf("DHCP:  ");
        }
        else 
        {
            printf("BOOTP");
        } 
    }
    return end;
}