#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "link/ethernet.h"
#include "net/ethernet.h"
#include "network/ipv4.h"
#include "network/ipv6.h"
#include "network/arp.h"

static void packetHandler(u_char* user, const struct pcap_pkthdr* header, const unsigned char* bytes)
{
    int verbosity = *((int*)user);
    uint16_t ether_type;
    uint8_t ip_protocol;
    const unsigned char* end = bytes + header->caplen;
    // display ethernet and move pointer to first byte of next protocol
    if((bytes = parse_ethernet_header(bytes, end, verbosity, &ether_type)) == NULL)
    {
        fprintf(stderr, "cannot parse ethernet header");
        return;
    }
    switch(ether_type)
    {
        case ETHERTYPE_IP:

            bytes = parse_ipv4_header(bytes, end, verbosity, &ip_protocol);
            break;
        case ETHERTYPE_IPV6:
            bytes = parse_ipv6_header(bytes, end, verbosity, &ip_protocol);
            break;
        case ETHERTYPE_ARP:
            parse_arp_header(bytes, end, verbosity);
            return;
            break;
    }
}

int read_capture(int verbosity, char* interface_name, char* filter, char* offline_filename)
{
    int r;
    int return_code = EXIT_FAILURE;
    pcap_t* session = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);

    if(offline_filename != NULL)
    {
        if((session = pcap_open_offline(offline_filename, errbuf)) == NULL)
        {
            fprintf(stderr, "%s\n", errbuf);
            goto CLOSE;
        }
    }
    else
    {
        if(interface_name == NULL)
        {
            fprintf(stderr, "interface or offline should be specified\n");
            goto CLOSE;
        }

        printf("Scanning interface: %s\n", interface_name);

        if((session = pcap_create(interface_name, errbuf)) == NULL)
        {
            fprintf(stderr, "%s\n", errbuf);
            goto CLOSE;
        }

        if(pcap_set_immediate_mode(session, 1))
        {
            pcap_perror(session, "Set immediate mode error: ");
            goto CLOSE;
        }
        if(pcap_set_promisc(session, 1))
        {
            pcap_perror(session, "Set promisc mode error: ");
            goto CLOSE;
        }

        if((r = pcap_activate(session)))
        {
            if(r < 0)
            {
                pcap_perror(session, "Activation error: ");
                goto CLOSE;
            }
            else
            {
                pcap_perror(session, "Activation warning: ");
            }
        }
    }

    if(filter != NULL)
    {
        struct bpf_program compiled_filter;
        bpf_u_int32 ip, mask;
        if(pcap_lookupnet(interface_name, &ip, &mask, errbuf))
        {
            fprintf(stderr, "%s\n", errbuf);
            goto CLOSE;
        }
        if(pcap_compile(session, &compiled_filter, filter, 0, mask))
        {
            pcap_perror(session, "Filter compilation error: ");
            goto CLOSE;
        }
        if(pcap_setfilter(session, &compiled_filter))
        {
            pcap_perror(session, "Filter can't be set: ");
            goto CLOSE;
        }
    }

    printf("Starting Capture\n\n");
    int loop;
    if((loop = pcap_dispatch(session, -1, packetHandler, (u_char*)(&verbosity))) < 0)
    {
        fprintf(stderr, "\npcap_loop() failed : %s\n", pcap_geterr(session));
        goto CLOSE;
    }

    return_code = EXIT_SUCCESS;
CLOSE:
    if(session != NULL)
    {
        pcap_close(session);
        session = NULL;
    }

    return return_code;
}
