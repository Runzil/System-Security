#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <getopt.h>

#include <signal.h>
#include <unistd.h>


struct FlowInfo { //structure to track flow info
    in_addr_t src_ip;    // source IPv4 address and port
    in_port_t src_port;

    in_addr_t dst_ip;    // destination IPv4 address and port
    in_port_t dst_port;
    
    struct in6_addr src_ip6;  // source IPv6 address and port
    in_port_t src_port6;
    struct in6_addr dst_ip6;  // destination IPv6 address and port
    in_port_t dst_port6;

    uint32_t last_seq;  // last sequence number
    uint32_t last_ack;  // last acknowledgment number
};

// vars for filtering port and flag
in_port_t filter_port;

bool filter_enabled;

// statistics (output) vars
int tcp_flows = 0;
int udp_flows = 0;
int total_packets = 0;
int tcp_packets = 0;
int udp_packets = 0;
int total_tcp_bytes = 0;
int total_udp_bytes = 0;

// filtered vars statistics
int filtered_tcp_flows = 0;
int filtered_udp_flows = 0;
int filtered_tcp_packets = 0;
int filtered_udp_packets = 0;
int filtered_tcp_bytes = 0;
int filtered_udp_bytes = 0;

// function to handle packets
void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct FlowInfo *flow_info = (struct FlowInfo *)user;     // casting user data to our flow info structure

    uint16_t ether_type = ntohs(*(uint16_t *)(packet + 12)); // assuming Ethernet frames, checking the Ethernet type for IPv4 (0x0800) and IPv6 (0x86DD)

    total_packets++;  // increment total packets

    if (ether_type == 0x0800) { // IPv4
        struct ip *ip_header = (struct ip *)(packet + 14);


        // TCP packet
        if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_flows++;
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + 4 * ip_header->ip_hl);

        // incrementing total TCP packets count and total TCP bytes
        tcp_packets++;
        total_tcp_bytes += pkthdr->len;

            // checking if filtering is enabled and the destination port matches the specified filter_port
            if (!filter_enabled || ntohs(tcp_header->th_dport) == filter_port || ntohs(tcp_header->th_sport) == filter_port) { 
                uint32_t current_seq = ntohl(tcp_header->th_seq);
                uint32_t current_ack = ntohl(tcp_header->th_ack);

                int tcp_header_len = tcp_header->th_off *4; // calculating TCP header length in bytes

                int tcp_payload_len = pkthdr->len - (14 + 4 * ip_header->ip_hl + tcp_header_len);


                // checking if it's a retransmitted packet
                if (current_seq < flow_info->last_seq || current_ack < flow_info->last_ack) {
                    printf("Retransmitted IPv4 TCP Packet - Src: %s:%d, Dst: %s:%d, HeaderLen: %d, PayloadLen: %d, Payload Memory Location: %p\n",
                           inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport),
                           inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport),
                           tcp_header_len, tcp_payload_len,
                           packet + 14 + ip_header->ip_hl*4 + tcp_header_len);
                } else {
                    printf("IPv4 TCP Packet - Src: %s:%d, Dst: %s:%d, HeaderLen: %d, PayloadLen: %d, Payload Memory Location: %p\n",
                           inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport),
                           inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport),
                           tcp_header_len, tcp_payload_len,
                           packet + 14 + ip_header->ip_hl*4 + tcp_header_len);
                }

                // updating the last sequence and acknowledgment numbers
                flow_info->last_seq = current_seq;
                flow_info->last_ack = current_ack;

                // updating the filtered statistics
                if (filter_enabled) {
                    filtered_tcp_flows++;
                    filtered_tcp_packets++;
                    filtered_tcp_bytes += pkthdr->len;
                }
            }
        }
        // if its UDP packet
        else if (ip_header->ip_p == IPPROTO_UDP) {
            udp_flows++;
            struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl*4));
            // incrementing total UDP packets count and total UDP bytes
            udp_packets++; 
            total_udp_bytes += pkthdr->len;

            // checking if filtering is enabled and the destination port matches the specified filter_port
            if (!filter_enabled || ntohs(udp_header->uh_dport) == filter_port || ntohs(udp_header->uh_sport) == filter_port) {
                int udp_header_len = 8; // UDP header length in bytes

                int udp_payload_len = ntohs(udp_header->uh_ulen) - udp_header_len; // UDP payload length in bytes


                printf("IPv4 UDP Packet - Src: %s:%d, Dst: %s:%d, HeaderLen: %d, PayloadLen: %d, Payload Memory Location: %p\n",
                       inet_ntoa(ip_header->ip_src), ntohs(udp_header->uh_sport),
                       inet_ntoa(ip_header->ip_dst), ntohs(udp_header->uh_dport),
                       udp_header_len, udp_payload_len,
                       packet + 14 + ip_header->ip_hl*4 + udp_header_len);

                // updating the filtered statistics
                if (filter_enabled) {
                    filtered_udp_flows++;
                    filtered_udp_packets++;
                    filtered_udp_bytes += pkthdr->len;
                }
            }
        }
    } else if (ether_type == 0x86DD) { // IPv6
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + 14);

        
        // if it is IPv6 TCP packet
        if (ip6_header->ip6_nxt == IPPROTO_TCP) {
            tcp_flows++;
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + sizeof(struct ip6_hdr));

            // incrementing total TCP packets count and total TCP bytes
            tcp_packets++;
            total_tcp_bytes += pkthdr->len;

            // checking if filtering is enabled and the destination port matches the specified filter_port
            if (!filter_enabled || ntohs(tcp_header->th_dport) == filter_port || ntohs(tcp_header->th_sport) == filter_port) {
                uint32_t current_seq = ntohl(tcp_header->th_seq);
                uint32_t current_ack = ntohl(tcp_header->th_ack);

                // calculating TCP payload length in bytes
                int tcp_payload_len = pkthdr->len - (14 + sizeof(struct ip6_hdr) + sizeof(struct tcphdr));

                // checking if it's a retransmitted packet
                char src_ip6_str[INET6_ADDRSTRLEN];
                char dst_ip6_str[INET6_ADDRSTRLEN];

                if (inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip6_str, INET6_ADDRSTRLEN) == NULL ||
                    inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip6_str, INET6_ADDRSTRLEN) == NULL) {
                    perror("inet_ntop");
                    exit(1); // fail
                }

                if (current_seq < flow_info->last_seq || current_ack < flow_info->last_ack) {
                    printf("Retransmitted IPv6 TCP Packet - Src: %s, Src Port: %d, Dst: %s, Dst Port: %d, HeaderLen: %ld, PayloadLen: %d, Payload Memory Location: %p\n",
                           src_ip6_str, ntohs(tcp_header->th_sport), dst_ip6_str, ntohs(tcp_header->th_dport),
                           sizeof(struct tcphdr), tcp_payload_len,
                           packet + 14 + sizeof(struct ip6_hdr) + sizeof(struct tcphdr));
                } else {
                    printf("IPv6 TCP Packet - Src: %s, Src Port: %d, Dst: %s, Dst Port: %d, HeaderLen: %ld, PayloadLen: %d, Payload Memory Location: %p\n",
                           src_ip6_str, ntohs(tcp_header->th_sport), dst_ip6_str, ntohs(tcp_header->th_dport),
                           sizeof(struct tcphdr), tcp_payload_len,
                           packet + 14 + sizeof(struct ip6_hdr) + sizeof(struct tcphdr));
                }

                // updating the last sequence and acknowledgment numbers
                flow_info->last_seq = current_seq;
                flow_info->last_ack = current_ack;

                // updating the filtered statistics
                if (filter_enabled) {
                    filtered_tcp_flows++;
                    filtered_tcp_packets++;
                    filtered_tcp_bytes += pkthdr->len;
                }
            }
        }
        // if its IPv6 UDP packet
        else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            udp_flows++;
            struct udphdr *udp_header = (struct udphdr *)(packet + 14 + sizeof(struct ip6_hdr));

            // incrementing total UDP packets count and total UDP bytes
            udp_packets++;
            total_udp_bytes += pkthdr->len;

            // checking if filtering is enabled and the destination port matches the specified filter_port
            if (!filter_enabled || ntohs(udp_header->uh_dport) == filter_port || ntohs(udp_header->uh_sport) == filter_port) {
                // calculating UDP payload length in bytes
                int udp_payload_len = pkthdr->len - (14 + sizeof(struct ip6_hdr) + sizeof(struct udphdr));

                char src_ip6_str[INET6_ADDRSTRLEN];
                char dst_ip6_str[INET6_ADDRSTRLEN];

                if (inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip6_str, INET6_ADDRSTRLEN) == NULL ||
                    inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip6_str, INET6_ADDRSTRLEN) == NULL) {
                    perror("inet_ntop");
                    exit(1); // fail
                }

                printf("IPv6 UDP Packet - Src: %s, Src Port: %d, Dst: %s, Dst Port: %d, HeaderLen: %ld, PayloadLen: %d, Payload Memory Location: %p\n",
                       src_ip6_str, ntohs(udp_header->uh_sport), dst_ip6_str, ntohs(udp_header->uh_dport),
                       sizeof(struct udphdr), udp_payload_len,
                       packet + 14 + sizeof(struct ip6_hdr) + sizeof(struct udphdr));

                // updating the filtered statistics
                if (filter_enabled) {
                    filtered_udp_flows++;
                    filtered_udp_packets++;
                    filtered_udp_bytes += pkthdr->len;
                }
            }
        }
    }
}

// function for printng
void print_statistics() {
if (filter_enabled) {  // printing filtered statistics only when filtering is enabled

    printf("\nfiltered statistics:\n");
    printf("total number of filtered network flows: %d\n", filtered_tcp_flows + filtered_udp_flows);
    printf("number of filtered TCP network flows: %d\n", filtered_tcp_flows);
    printf("number of filtered UDP network flows: %d\n", filtered_udp_flows);
    printf("total number of unfiltered total packets: %d\n", total_packets);
    printf("total number of filtered TCP packets: %d\n", filtered_tcp_packets);
    printf("total number of filtered UDP packets: %d\n", filtered_udp_packets);
    printf("total bytes of filtered TCP packets: %d\n", filtered_tcp_bytes);
    printf("total bytes of filtered UDP packets: %d\n", filtered_udp_bytes);
} else {
    printf("\nstatistics on exit:\n");
    printf("total number of network flows: %d\n", tcp_flows+udp_flows);
    printf("number of TCP network flows: %d\n", tcp_flows);
    printf("number of UDP network flows: %d\n", udp_flows);
    printf("total number of packets: %d\n", total_packets);
    printf("total number of TCP packets: %d\n", tcp_packets);
    printf("total number of UDP packets: %d\n", udp_packets);
    printf("total bytes of TCP packets: %d\n", total_tcp_bytes);
    printf("total bytes of UDP packets: %d\n", total_udp_bytes);
}
}

void interrupt_handler(int signo) {
    if (signo == SIGINT) {
        printf("\nReceived Ctrl+C. Printing statistics and exiting...\n");
        print_statistics();
        exit(0);
    }
}

// help message
void print_help(char *program_name) {
    printf("usage: %s -i <interface> OR %s -r <file.pcap> [-f <port>] OR %s -h\n", program_name, program_name, program_name);
    printf("-i: select the network interface name (e.g., eth0 (depends on available interfaces) )\n");
    printf("-r: packet capture file name (e.g., test.pcap)\n");
    printf("-f: filter expression in string format (e.g., port 8080 (for filtering port 8080) )\n");
    printf("-h: help message, which shows the usage of each parameter\n");
}



// main function
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; // size = 256
    pcap_t *handle;
    int option;

    // initialize flow information
    struct FlowInfo flow_info = {0};

    // options
    char *interface = NULL;
    char *file = NULL;
    char *filter = NULL;

    // file pointer for the log file
    FILE *logfile = NULL;

    // register the interrupt handler
    if (signal(SIGINT, interrupt_handler) == SIG_ERR) {
        fprintf(stderr, "Unable to register interrupt handler.\n");
        exit(1);
    }

    // parsing command line options
    while ((option = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (option) {
            case 'i':
                interface = optarg;
                break;
            case 'r':
                file = optarg;
                break;
            case 'f':
                filter = optarg;
                break;
            case 'h':
                print_help(argv[0]);
                exit(0); // success
            default:
                fprintf(stderr, "Invalid input, use %s -h for help.\n", argv[0]);
                exit(1); // fail
        }
    }

    // checking for mandatory options
    if ((interface == NULL && file == NULL) || (interface != NULL && file != NULL)) {
        fprintf(stderr, "specify either an interface (-i) or a file (-r).\n");
        exit(1);
    }

    // redirect stdout to log.txt if using -i
    if (interface != NULL) {
        logfile = fopen("log.txt", "w");
        if (logfile == NULL) {
            perror("fopen");
            exit(1); // fail
        }
        // redirect stdout to log.txt
        dup2(fileno(logfile), STDOUT_FILENO);
        setbuf(stdout, NULL);  // disable buffering for immediate output
    }

    // opening the capture file or live capture

    if (interface != NULL) {
        // capture live traffic
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    } else {
        // read from a pcap file
        handle = pcap_open_offline(file, errbuf);
    }

    // check if the handle is initialized
    if (handle == NULL) {
        fprintf(stderr, "could not open device/file: %s\n", errbuf);
        exit(1); // fail
    }

    // set the default filter values
    filter_enabled = false;
    filter_port = 0;

    // parse the optional port argument if provided
    if (filter != NULL) {
        filter_enabled = true;

        // parse the filter expression in string format
        if (sscanf(filter, "port %hu", &filter_port) != 1) {
            fprintf(stderr, "Invalid filter expression. Use '-f port <port_number>'.\n");
            exit(1);
        }
    }

    // loop through packets and call the packet_handler for each packet
    pcap_loop(handle, 0, packet_handler, (unsigned char *)&flow_info);

    // close capture handle
    pcap_close(handle);

    // print statistics
    print_statistics();

    // close the log file if it was opened for -i
    if (logfile != NULL && logfile != stdout) {
        fclose(logfile);
    }

    return 0;
}

