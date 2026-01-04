#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "parser.h"

/*
    Dataplane action to do when a packet matches a flow rule.
*/
typedef enum {
    ACT_DROP = 0,
    ACT_FWD = 1
} action_type_t;

typedef struct {
    action_type_t type;

    /*
        out_ifindex is the Linux interface index(an integer) returned by if_nametoindex().
        Index is used rather than name because it hashes well and is faster to compare.
    */
    int out_ifindex;
} flow_action_t;

typedef struct {
    bool used; // to make sure slot is empty before inserting new flow
    flow_key_t key;
    flow_action_t action;
} flow_entry_t;

typedef struct {
    flow_entry_t *entries; // allocated entries
    size_t capacity;       // number of slots (must be power of two)
    size_t size;           // number of used slots
} flow_table_t;

/*
    Initialize a flow table with a given capacity.

    Requirement:
        - Capacity must be a power of two for hash table
          optimization.

    Returns 0 on success, -1 on failure.
*/
int flow_table_init(flow_table_t *t, size_t capacity);

/*
    Free internal memory used by the flow table.
*/
void flow_table_destroy(flow_table_t *t);

/*
    Insert or update a flow entry in the flow table.

    Returns 0 on success, -1 on failure.
*/
int flow_table_put(flow_table_t *t, const flow_key_t *key, const flow_action_t *action);

/*
    Lookup a flow entry in the flow table.

    Returns true if found and writes to *out_action, false if not found.
*/
bool flow_table_get(const flow_table_t *t, const flow_key_t *key, flow_action_t *out_action);

#endif