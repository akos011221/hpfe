#ifndef RX_H
#define RX_H

#include <stddef.h>
#include <stdint.h>

/*
    Start packet capture on an interface.
    Blocks until pkt is stopped by signal.
*/
int rx_start(const char *iface);

#endif