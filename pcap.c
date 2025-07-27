#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr
{
        u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
        u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
        u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
        u_int8_t ip_hl : 4,      /* header length */
                ip_v : 4;         /* version */
        u_int8_t ip_tos;       /* type of service */
        u_int16_t ip_len;         /* total length */
        u_int16_t ip_id;          /* identification */
        u_int16_t ip_off;
        u_int8_t ip_ttl;          /* time to live */
        u_int8_t ip_p;            /* protocol */
        u_int16_t ip_sum;         /* checksum */
        struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
        u_int16_t th_sport;       /* source port */
        u_int16_t th_dport;       /* destination port */
        u_int32_t th_seq;          /* sequence number */
        u_int32_t th_ack;          /* acknowledgement number */
        u_int8_t th_x2 : 4,         /* (unused) */
                th_off : 4;        /* data offset */
        u_int8_t  th_flags;       /* control flags */
        u_int16_t th_win;         /* window */
        u_int16_t th_sum;         /* checksum */
        u_int16_t th_urp;         /* urgent pointer */
};

void usage() {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
}

typedef struct {
        char* dev_;
} Param;

Param param = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
        if (argc != 2) {
                usage();
                return false;
        }
        param->dev_ = argv[1];
        return true;
}

int main(int argc, char* argv[]) {
        struct libnet_ethernet_hdr * ethernet_hdr;
        struct libnet_ipv4_hdr* ipv4_hdr;
        struct libnet_tcp_hdr* tcp_hdr;

        if (!parse(&param, argc, argv))
                return -1;

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
        if (pcap == NULL) {
                fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
                return -1;
        }

        while (true) { // GPT
                struct pcap_pkthdr* header;
                const u_char* packet;
                int res = pcap_next_ex(pcap, &header, &packet);
                if (res == 0) continue;
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                        break;
                }

                ethernet_hdr = (struct libnet_ethernet_hdr*)packet;
                ipv4_hdr = (struct libnet_ipv4_hdr*)(packet + 14);
                int ip_len = ipv4_hdr->ip_hl * 4;
                tcp_hdr = (struct libnet_tcp_hdr*)(packet + 14 + ip_len);
                int tcp_len = tcp_hdr->th_off * 4;

                for (int i = 0; i < 6; i++) {
                        printf("%02x", ethernet_hdr->ether_shost[i]);
                        if (i < 5)
                                printf(": ");
                }
                printf("-> ");
                for (int i = 0; i < 6; i++) {
                        printf("%02x", ethernet_hdr->ether_dhost[i]);
                        if (i < 5)
                                printf(": ");
                }

                printf(", ");
                printf("%s ", inet_ntoa(ipv4_hdr->ip_src));
                printf("-> ");
                printf("%s ", inet_ntoa(ipv4_hdr->ip_dst));
                printf(", ");

                printf("%d ", ntohs(tcp_hdr->th_sport));
                printf("-> ");
                printf("%d ", ntohs(tcp_hdr->th_dport));
                printf(", ");

                int total_ip_len = ntohs(ipv4_hdr->ip_len);
                int payload_offset = 14 + ip_len + tcp_len;
                int payload_len = total_ip_len - ip_len - tcp_len;

                if (payload_len > 0) {
                        int to_print = payload_len > 20 ? 20 : payload_len;
                        for (int i = 0; i < to_print; i++) {
                                printf("%02x|", packet[payload_offset + i]);
                        }
                }

                else {
                        printf("\n -");
                }

                printf("\n ========================================================\n");
        }

        pcap_close(pcap);
}
