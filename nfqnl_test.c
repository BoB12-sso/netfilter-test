#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>

#define NF_DROP 0
#define NF_ACCEPT 1

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

static u_int32_t print_pkt(struct nfq_data *tb) {
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(tb);
    return ntohl(ph->packet_id);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, char *hostname) {
    u_int32_t id = print_pkt(nfa);

    int payload_len;
    unsigned char *payload;
    if ((payload_len = nfq_get_payload(nfa, &payload)) >= 0) {
        struct iphdr *ip_header = (struct iphdr *)payload;
        if (ip_header->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(payload + ip_header->ihl * 4);
            int tcp_header_len = tcp_header->doff * 4;
            int total_header_len = ip_header->ihl * 4 + tcp_header_len;
            if (payload_len > total_header_len + 4 && payload[total_header_len] == 'G' &&
                payload[total_header_len + 1] == 'E' && payload[total_header_len + 2] == 'T') {
                char *host = strstr(payload + total_header_len, "Host: ");
                if (host) {
                    host += 6;
                    char *end = strchr(host, '\r');
                    if (end) {
                        *end = '\0';
                        if (strcmp(host, hostname) == 0) {
                            printf("Blocking packet with id: %u\n", id);
                            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                        }
                    }
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char *argv[]) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, argv[1]);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0) {
            perror("recv failed");
            break;
        }
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
