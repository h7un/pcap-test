#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <libnet.h>

// Print usage information
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

// Define a structure and a global variable to store program parameters
typedef struct {
    char* dev_;
} Param;

Param param = { .dev_ = NULL };

// Parse command-line arguments to get the interface name
bool parse(Param* param, int argc, char* argv[]) {
    // If there are not enough arguments, print usage information and return false
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

// Function to print MAC address
void print_mac(const char* label, const u_char* mac) {
    printf("%s %02x:%02x:%02x:%02x:%02x:%02x\n", label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Function to print IP address
void print_ip(const char* label, uint32_t ip) {
    printf("%s %s\n", label, inet_ntoa(*(struct in_addr*)&ip));
}

// Function to print the first 20 bytes of the payload in hexadecimal
void print_payload(const u_char* payload, int len) {
    printf("Payload (Hex): ");
    for (int i = 0; i < len && i < 20; ++i) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv)) return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); // Start capturing packets on the specified interface
    if (!pcap) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        // Capture packet and extract Ethernet, IP, and TCP headers
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex returned %d: %s\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
            struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
            if (ip_hdr->ip_p == IPPROTO_TCP) { // Only print if it's a TCP packet
                struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl * 4));

                print_mac("Src MAC:", eth_hdr->ether_shost);
                print_mac("Dst MAC:", eth_hdr->ether_dhost);
                print_ip("Src IP:", ip_hdr->ip_src.s_addr);
                print_ip("Dst IP:", ip_hdr->ip_dst.s_addr);
                printf("Src Port: %d\n", ntohs(tcp_hdr->th_sport));
                printf("Dst Port: %d\n", ntohs(tcp_hdr->th_dport));

                const u_char* payload = (u_char*)tcp_hdr + (tcp_hdr->th_off * 4);
                int payload_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - (tcp_hdr->th_off * 4);
                print_payload(payload, payload_len);
            }
        }
        // Print the number of bytes captured
        printf("%u bytes captured\n", header->caplen);
    }

    // Close the pcap handle
    pcap_close(pcap);
    return 0;
}
