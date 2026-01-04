#ifndef UPE_H
#define UPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "flow_table.h"

typedef struct {
    const char *iface; // interface name
    int verbose;       // 0..2
    int duration_sec;  // 0 = run forever

    flow_table_t ft;
} upe_config_t;

#endif