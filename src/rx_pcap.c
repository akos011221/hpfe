#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include "log.h"
#include "parser.h"
#include "rx.h"

#include <errno.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pcap_t *g_pcap = NULL;

static void process_packet(const uint8_t *pkt, size_t len) {
    ipv4_info_t info;
    if (parse_ipv4(pkt, len, &info) == 0) {
        log_msg(LOG_DEBUG, "IPv4 %u.%u.%u.%u -> %u.%u.%u.%u proto=%u", (info.src_ip >> 24) & 0xFF,
                (info.src_ip >> 16) & 0xFF, (info.src_ip >> 8) & 0xFF, info.src_ip & 0xFF,
                (info.dst_ip >> 24) & 0xFF, (info.dst_ip >> 16) & 0xFF, (info.dst_ip >> 8) & 0xFF,
                info.dst_ip & 0xFF, info.protocol);
    }
}

static void pcap_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes) {
    (void)user;
    process_packet(bytes, hdr->caplen);
}

int rx_start(const char *iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap = pcap_open_live(iface, 65535, 1, 1, errbuf);

    if (!g_pcap) {
        log_msg(LOG_ERROR, "pcap_open_live failed: %s", errbuf);
        return -1;
    }

    log_msg(LOG_INFO, "RX started on %s", iface);

    int rc = pcap_loop(g_pcap, -1, pcap_callback, NULL);

    log_msg(LOG_WARN, "pcap_loop exited: %d", rc);
    return 0;
}

void rx_stop(void) {
    if (g_pcap) {
        pcap_breakloop(g_pcap);
    }
}