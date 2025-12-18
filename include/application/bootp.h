#ifndef BOOTP_H
#define BOOTP_H 
#include <stdint.h>

enum DHCP_MESSAGE_TYPES
{
    DHCP_DISCOVER = 1,
    DHCP_OFFER = 2,
    DHCP_REQUEST = 3,
    DHCP_DECLINE = 4,
    DHCP_ACK = 5,
    DHCP_NACK = 6,
    DHCP_RELEASE = 7,
    DHCP_INFORM = 8,
    DHCP_FORCE_RENEW = 9,
    DHCP_LEASE_QUERY = 10,
    DHCP_LEASE_UNASSIGNED = 11,
    DHCP_LEASE_UNKNOWN = 12,
    DHCP_LEASE_ACTIVE = 13,
    DHCP_BULK_LEASE_QUERY = 14,
    DHCP_LEASE_QUERY_DONE = 15,
    DHCP_ACTIVE_LEASE_QUERY = 16,
    DHCP_LEASE_QUERY_STATUS = 17,
    DHCP_TLS = 18
};
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
//TODO: add all dhcp options from rfc 2132 and handle them 
//this is a non complete list of dhcp options but it contains the most
//important ones 
enum DHCP_OPTIONS
{
    DHCP_NOP = 0,                   
    DHCP_SUBNET_MASK = 1,           
    DHCP_TIME_OFFSET = 2 ,          
    DHCP_ROUTER = 3 ,                
    DHCP_DOMAIN_NAME_SERVER = 6,     
    DHCP_HOSTNAME = 12,           
    DHCP_DOMAIN_NAME = 15,
    DHCP_NTP_SERVERS = 42,
    DHCP_ADDRESS_REQUEST = 50,
    DHCP_LEASE_TIME = 51,
    DHCP_MESSAGE_TYPE = 53,
    DHCP_SERVER_ID = 54,
    DHCP_PARAMETER_REQUEST_LIST = 55,
    DHCP_RENEWAL = 58,
    DHCP_REBINDING = 59,
    DHCP_CLIENT_ID = 61,
    DHCP_END = 255 
};

struct bootphdr 
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen; 
    uint8_t hops;
    uint32_t xid;
    uint16_t secs ;
    uint16_t flags ;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file [128];
    uint8_t vend[64];
};
void parse_dhcp_tlv(const unsigned char* start, const unsigned char* end);
const unsigned char* parse_bootp_header(const unsigned char* bytes, const unsigned char* end, int verbosity);
#endif