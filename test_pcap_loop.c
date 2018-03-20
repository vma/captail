/* test_pcap_loop.c - pcap_loop() example of use.
 *
 * Copyright (c) 2018 - SIP Solutions.
 * Author: Vallimamod Abdullah <vma@sipsolutions.fr>
 */

#include <pcap/pcap.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void dbg(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "DBG: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (fmt[strlen(fmt) - 1] != '\n') {
        fprintf(stderr, "\n");
    }
}

void pcap_cb(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    fprintf(stderr, "Packet capture length: %d\n", h->caplen);
    fprintf(stderr, "Packet total length: %d\n", h->len);
    write(1, bytes, h->caplen);
}

int main(int argc, char **argv) {
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t *p;
    int rv;

    dbg("open stdin...");
    p = pcap_open_offline("-", err_buf);
    dbg("after open, p=%p errbuf=%s", p, err_buf);
    rv = pcap_loop(p, 0, pcap_cb, NULL);
    if (rv < 0) {
        pcap_perror(p, "ERR: pcap_loop");
        return -1;
    }
    pcap_close(p);
    return 0;
}
