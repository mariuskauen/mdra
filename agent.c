#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

void my_packet_handler(__u_char *args, const struct pcap_pkthdr *header, const __u_char *packet);
void print_packet_info(const __u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char *argv[])
{
    char error[PCAP_ERRBUF_SIZE];
    char *device;
    char ip[13];
    char subnet_mask[13];
    bpf_u_int32 ip_raw;
    bpf_u_int32 subnet_mask_raw;
    int lookup_return_code;
    struct in_addr address;
    const __u_char *packet;
    pcap_if_t *interfaces;
    pcap_t *handle;
    int snapshot_len = 1028;
    int promiscuous = 1;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout = 10000;
    char filter_exp[] = "udp";
    struct bpf_program filter;

    if (pcap_findalldevs(&interfaces, error) == -1)
    {
        printf("\n");
        printf("No interface found!\n");
    }
    device = interfaces->name;
    printf("Listening on interface: %s\n", device);
    printf("===========================================\n");
    printf("Interface information: \n");
    lookup_return_code = pcap_lookupnet(device, &ip_raw, &subnet_mask_raw, error);
    if (lookup_return_code == -1)
    {
        printf("%s\n", error);
        return 1;
    }
    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL)
    {
        perror("inet_ntoa");
        return 1;
    }
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL)
    {
        perror("inet_ntoa");
        return 1;
    }
    printf("Device: %s\n", device);
    printf("Interface IP address: ");
    printf("Network IP address: %s\n", ip);
    printf("Subnet mask: %s\n", subnet_mask);
    printf("===========================================\n\n");

    // handle = pcap_open_live(device, snapshot_len, promiscuous,timeout,error);
    // if(handle == NULL)
    // {
    //     printf("Could not open!\n");
    //     return 1;
    // }

    handle = pcap_create(device, error);
    if (handle == NULL)
    {
        printf("Could not create handle.\n");
        return 1;
    }
    if (pcap_set_immediate_mode(handle, 1) == 0)
        printf("Immediate mode on. Captured packets are printed immediately.\n");
    else
        printf("Immediate mode off. Packets are buffered and is printed in groups.\n");

    if (pcap_set_timeout(handle, timeout) == 0)
        printf("Timeout set to %d ms.\n", timeout);
    else
        printf("Failed to set timeout.\n");

    if (pcap_set_snaplen(handle, snapshot_len) == 0)
        printf("Snapshot length set to %d.\n", snapshot_len);
    else
        printf("Failed to set snapshot length.\n");
    if (pcap_can_set_rfmon(handle) == 1)
    {
        if (pcap_set_rfmon(handle, 1) == 0)
            printf("Monitor mode on.\n");
        else
            printf("Failed to set monitor mode.\n");
    }
    else
        printf("Monitor mode off (Not supported by the interface).\n");

    if (pcap_set_promisc(handle, 1) == 0)
        printf("Promiscuous mode is on.\n");
    else
        printf("Promiscuous mode is off.\n");

    if (pcap_activate(handle) == 0)
        printf("Handle activated and ready to capture packets.\n");
    else
        printf("Activation of handle failed. Closing handle.\n");

    if(pcap_compile(handle, &filter, filter_exp,0,ip_raw)==-1)
    {
        printf("Bad filter - %s\n",pcap_geterr(handle));
        return 2;
    }
    if(pcap_setfilter(handle, &filter) == -1)
    {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }  
    else
    {
        printf("Filtering packets\n");
        printf("Filter:\n");
        printf("%s\n", filter_exp);
    }
    printf("\n");
    pcap_loop(handle, 0, my_packet_handler, NULL);
    pcap_close(handle);

    return 0;
}
void my_packet_handler(__u_char *args, const struct pcap_pkthdr *packet_header, const __u_char *packet_body)
{
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet_body;
    const __u_char *ip_header;
    //const __u_char *tcp_header;
    const __u_char *udp_header;
    const __u_char *payload;
    int ethernet_header_length = 14;
    int ip_header_length;
    //int tcp_header_length;
    int udp_header_length;
    int payload_length;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        printf("Not IP. Skipping.\n");
        return;
    }
    else
    {
        #pragma region TCP
        // ip_header = packet_body + ethernet_header_length;
        // ip_header_length = ((*ip_header) & 0x0F);
        // ip_header_length = ip_header_length * 4;
        // //printf("IP header length: %d ", ip_header_length);

        // __u_char protocol = *(ip_header + 9);
        // if (protocol != IPPROTO_TCP)
        // {
        //     printf("Not TCP. Skipping.\n");
        //     return;
        // }
        // tcp_header = packet_body + ethernet_header_length + ip_header_length;
        // tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;

        // tcp_header_length = tcp_header_length * 4;
        // //printf("TCP header length: %d ", tcp_header_length);

        // int total_header_size = ethernet_header_length + ip_header_length + tcp_header_length;
        // printf("Total header size: %d ", total_header_size);

        // payload_length = packet_header->caplen - total_header_size;
        // printf("Payload size: %d ", payload_length);

        // printf("Total packet size: %d", (total_header_size+payload_length));

        // printf("\n");
        // // For å printe payloaden
        // if(payload_length > 0)
        // {
        //     const __u_char *temp_pointer = payload;
        //     int byte_count = 0;
        //     while(byte_count++<payload_length)
        //     {
        //         printf("%c",*temp_pointer);
        //         temp_pointer++;
        //     }
        //     printf("\n");
        // }
        #pragma endregion
    
        ip_header = packet_body + ethernet_header_length;
        ip_header_length = ((*ip_header) & 0x0F);
        ip_header_length = ip_header_length * 4;

        __u_char protocol = *(ip_header + 9);
        if (protocol != IPPROTO_UDP)
        {
            printf("Not UDP. Skipping.\n");
            return;
        }

        udp_header = packet_body + ethernet_header_length + ip_header_length;

    }

    return;
}
void print_packet_info(const __u_char *packet, struct pcap_pkthdr packet_header)
{
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}