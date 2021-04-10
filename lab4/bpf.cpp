#include <iostream>
#include <sys/types.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <string>
#include <string.h>
#include <vector>
#include <netinet/ip.h>
using namespace std;

void got_packet(u_char *, const struct pcap_pkthdr *header, const u_char *packet);
string filter_exp;

int main(int argc, char *argv[])
{
    /// List interfaces
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1)
    {
        fprintf(stderr, "Can't get ifaddr list\n");
        return -1;
    }
    int family;
    vector<string> ifs;
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        family = ifa->ifa_addr->sa_family;
        if (ifa->ifa_addr == NULL || family != AF_INET)
            continue;
        ifs.push_back(string(ifa->ifa_name));
    }
    freeifaddrs(ifaddr);

    /// Get target interface
    u_int num;
    string dev;
    printf("There are %lu IPv4 interfaces:\n", ifs.size());
    for (u_int i = 0; i < ifs.size(); ++i)
        printf("[%u] %s\n", i + 1, ifs.at(i).c_str());

    while (1)
    {
        printf("Listen on interface: ");
        cin >> num;
        if (num > ifs.size())
            printf("Invalid interface\n");
        else
        {
            dev = ifs.at(num - 1);
            break;
        }
    }

    /// Listen on interface
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(dev.c_str(), &net, &mask, errbuf) == -1) // Get netmask of device
    {
        fprintf(stderr, "Can't get netmask for device %s\n", dev.c_str());
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev.c_str(), errbuf);
        return -1;
    }
    printf("Listening to %s ...\n", dev.c_str());
    getline(cin, filter_exp);
    while (1)
    {
        printf("Input filter: ");
        getline(cin, filter_exp);
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) != -1)
            break;
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
    }

    printf("Parsed filter with expression: %s ...\n", filter_exp.c_str());
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
        return -1;
    }
    printf("Filter installed ...\n");

    /// Parse packets
    while (1)
    {
        pcap_loop(handle, 0, got_packet, (u_char *)handle);
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1)
        {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
            break;
        }
        printf("Parsed filter with expression: %s ...\n", filter_exp.c_str());
        if (pcap_setfilter(handle, &fp) == -1)
        {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
            break;
        }
        printf("Filter installed ...\n");
    }
    pcap_close(handle);
    printf("End filtering\n");
    return 0;
}

/* Ethernet header */
struct ethernet
{
#define ETHER_ADDR_LEN 6
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header
{
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                /* total length */
    u_short ip_id;                 /* identification */
    u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* don't fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_proto;               /* protocol */
    u_short ip_sum;                /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HDRLEN(i) (((i)->ip_vhl) & 0x0f)
#define IP_VERSION(i) (((i)->ip_vhl) >> 4)

/* ARP Header */
struct arp_header
{
    u_short htype;
    u_short ptype;
    u_char hlen;
    u_char plen;
    u_short oper;
    u_char address[20]; /* Source MAC (6 bytes), Source IP (4 bytes), Dest MAC (6 bytes), Dest IP (4 bytes) */
};

/* GRE Header */
struct gre_header
{
    u_short check;
    u_short proto;
};

void got_packet(u_char *handle, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int cnt = 1, gre_num = 1;
    static bool bridge_up = false;
    printf("\nPacket [%d]\n", cnt++);

    for (int i = 0; i < header->len; ++i)
    {
        printf("%02x ", packet[i]);
        if (i % 8 == 7)
            printf("\n");
    }
    printf("\n");

    // Parse Ethernet header
    const ethernet *eth = (ethernet *)packet;
    const int ethhdr_size = 14;
    printf("Source MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; ++i)
    {
        printf("%02x ", eth->ether_shost[i]);
    }
    printf("\nDest MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; ++i)
    {
        printf("%02x ", eth->ether_dhost[i]);
    }
    printf("\nFrame Type: ");
    switch (eth->ether_type)
    {
    case 0x0008: // Little Endian
        printf("IPv4\n");
        break;
    case 0x0608:
        printf("ARP\n");
        break;
    default:
        printf("%04x\n", eth->ether_type);
        return;
    }

    // Parse IP Header
    if (eth->ether_type == 0x0008)
    {
        const ip_header *iphdr = (ip_header *)(packet + ethhdr_size);
        const int iphdr_size = IP_HDRLEN(iphdr) * 4;
        if (iphdr_size < 20)
        {
            fprintf(stderr, "Invalid ip header length: %d\n", iphdr_size);
            return;
        }
        printf("Source IP: %u.%u.%u.%u\n", iphdr->ip_src.s_addr & 0xff, (iphdr->ip_src.s_addr >> 8) & 0xff, (iphdr->ip_src.s_addr >> 16) & 0xff, (iphdr->ip_src.s_addr >> 24) & 0xff);
        printf("Dest IP: %u.%u.%u.%u\n", iphdr->ip_dst.s_addr & 0xff, (iphdr->ip_dst.s_addr >> 8) & 0xff, (iphdr->ip_dst.s_addr >> 16) & 0xff, (iphdr->ip_dst.s_addr >> 24) & 0xff);
        printf("Next layer protocol: ");
        switch (iphdr->ip_proto)
        {
        case 0x2f:
            printf("GRE\n");
            char s_ip[20], cmd[100];
            sprintf(s_ip, "%u.%u.%u.%u", iphdr->ip_src.s_addr & 0xff, (iphdr->ip_src.s_addr >> 8) & 0xff, (iphdr->ip_src.s_addr >> 16) & 0xff, (iphdr->ip_src.s_addr >> 24) & 0xff);

            if (strcmp(s_ip, "140.113.0.1") != 0)
            {
                // Build GRE tunnel
                sprintf(cmd, "ip link add GRE%d type gretap remote %s local 140.113.0.1", gre_num, s_ip);
                system(cmd);
                sprintf(cmd, "ip link set GRE%d up > /dev/null", gre_num);
                system(cmd);
                if (!bridge_up)
                {
                    system("ip link add br0 type bridge > /dev/null");
                    system("brctl addif br0 BRGr-eth0 > /dev/null");
                }
                sprintf(cmd, "brctl addif br0 GRE%d > /dev/null", gre_num);
                system(cmd);
                if (!bridge_up)
                    system("ip link set br0 up > /dev/null");
                bridge_up = true;
                sprintf(cmd, " and src host !%s", s_ip);
                filter_exp += cmd;
                gre_num++;
                pcap_breakloop((pcap_t *)handle);
            }
            break;
        case 0x01:
            printf("ICMP\n");
            break;
        case 0x06:
            printf("TCP\n");
            break;
        case 0x11:
            printf("UDP\n");
            break;
        default:
            printf("%02x", iphdr->ip_proto);
            break;
        }
        if (iphdr->ip_proto == 0x2f)
        {
            struct gre_header *grehdr = (gre_header *)(packet + ethhdr_size + iphdr_size);
            int grehdr_size = 4;
            if (grehdr->check != 0)
            {
                grehdr_size += 4;
            }
            if (grehdr->proto != 0x5865)
            {
                fprintf(stderr, "GRE protocol is not ethernet");
                exit(1);
            }
            else
            {
                printf("GRE protocol: Transparent Ethernet Bridging\n");
            }

            // Parse inner ethernet header
            printf("Encapsulated Packet:\n");
            const ethernet *in_eth = (ethernet *)(packet + ethhdr_size + iphdr_size + grehdr_size);
            const int in_ethhdr_size = 14;
            printf("Source MAC: ");
            for (int i = 0; i < ETHER_ADDR_LEN; ++i)
            {
                printf("%02x ", in_eth->ether_shost[i]);
            }
            printf("\nDest MAC: ");
            for (int i = 0; i < ETHER_ADDR_LEN; ++i)
            {
                printf("%02x ", in_eth->ether_dhost[i]);
            }
            printf("\nFrame Type: ");
            switch (in_eth->ether_type)
            {
            case 0x0008: // Little Endian
                printf("IPv4\n");
                break;
            case 0x0608:
                printf("ARP\n");
                break;
            case 0xdd86:
                printf("IPv6\n");
                break;
            default:
                printf("%04x\n", in_eth->ether_type);
                return;
            }

            // Parse inner IP header
            if (in_eth->ether_type == 0x0008)
            {
                const ip_header *in_iphdr = (ip_header *)(packet + ethhdr_size + iphdr_size + grehdr_size + in_ethhdr_size);
                const int in_iphdr_size = IP_HDRLEN(in_iphdr) * 4;
                if (in_iphdr_size < 20)
                {
                    fprintf(stderr, "Invalid ip header length: %d\n", in_iphdr_size);
                    return;
                }
                printf("Source IP: %u.%u.%u.%u\n", in_iphdr->ip_src.s_addr & 0xff, (in_iphdr->ip_src.s_addr >> 8) & 0xff, (in_iphdr->ip_src.s_addr >> 16) & 0xff, (in_iphdr->ip_src.s_addr >> 24) & 0xff);
                printf("Dest IP: %u.%u.%u.%u\n", in_iphdr->ip_dst.s_addr & 0xff, (in_iphdr->ip_dst.s_addr >> 8) & 0xff, (in_iphdr->ip_dst.s_addr >> 16) & 0xff, (in_iphdr->ip_dst.s_addr >> 24) & 0xff);
                printf("Next layer protocol: ");
                switch (in_iphdr->ip_proto)
                {
                case 0x01:
                    printf("ICMP\n");
                    break;
                case 0x06:
                    printf("TCP\n");
                    break;
                case 0x11:
                    printf("UDP\n");
                    break;
                default:
                    printf("%02x\n", in_iphdr->ip_proto);
                    break;
                }
            }

            // Parse inner ARP header
            else if (in_eth->ether_type == 0x0608)
            {
                const arp_header *arp = (arp_header *)(packet + ethhdr_size + iphdr_size + grehdr_size + in_ethhdr_size);
                printf("Operation: %s\n", (arp->oper == 0x0100) ? "Request" : "Reply");
                printf("Source MAC: ");
                for (int i = 0; i < ETHER_ADDR_LEN; ++i)
                {
                    printf("%02x ", arp->address[i]);
                }
                printf("\nSource IP: %u.%u.%u.%u\n", arp->address[6], arp->address[7], arp->address[8], arp->address[9]);
                printf("Dest MAC: ");
                for (int i = 10; i < 10 + ETHER_ADDR_LEN; ++i)
                {
                    printf("%02x ", arp->address[i]);
                }
                printf("\nDest IP: %u.%u.%u.%u\n", arp->address[16], arp->address[17], arp->address[18], arp->address[19]);
            }
        }
    }

    // Parse ARP Header
    else if (eth->ether_type == 0x0608)
    {
        const arp_header *arp = (arp_header *)(packet + ethhdr_size);
        printf("Operation: %s\n", (arp->oper == 0x0100) ? "Request" : "Reply");
        printf("Source MAC: ");
        for (int i = 0; i < ETHER_ADDR_LEN; ++i)
        {
            printf("%02x ", arp->address[i]);
        }
        printf("\nSource IP: %u.%u.%u.%u\n", arp->address[6], arp->address[7], arp->address[8], arp->address[9]);
        printf("Dest MAC: ");
        for (int i = 10; i < 10 + ETHER_ADDR_LEN; ++i)
        {
            printf("%02x ", arp->address[i]);
        }
        printf("\nDest IP: %u.%u.%u.%u\n", arp->address[16], arp->address[17], arp->address[18], arp->address[19]);
    }
    return;
}