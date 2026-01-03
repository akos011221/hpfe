#include "parser.h"
#include "log.h"
#include <arpa/inet.h>
#include <string.h>

struct eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
};

struct ipv4_hdr {
    uint8_t ver_ihl;
    uint8_t tos;
    uint8_t total_length;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

int parse_ipv4(const uint8_t *pkt, size_t len, ipv4_info_t *out) {
    if (len < sizeof(struct eth_hdr)) {
        return -1;
    }

    const struct eth_hdr *eth = (const struct eth_hdr *)pkt;

    uint16_t etype = ntohs(eth->ethertype);
    if (etype != 0x0800) {
        return -1;
    }

    const uint8_t *ip_ptr = pkt + sizeof(struct eth_hdr);
    size_t ip_len = len - sizeof(struct eth_hdr);

    if (ip_len < sizeof(struct ipv4_hdr)) {
        return -1;
    }

    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)ip_ptr;

    uint8_t version = ip->ver_ihl >> 4;
    uint8_t ihl = ip->ver_ihl & 0x0F;

    size_t total_hdr_len = ihl * 4;

    if (version != 4 || total_hdr_len < sizeof(struct ipv4_hdr) || ip_len < total_hdr_len) {
        return -1;
    }

    out->src_ip = ntohl(ip->src_ip);
    out->dst_ip = ntohl(ip->dst_ip);
    out->protocol = ip->protocol;

    return 0;
}