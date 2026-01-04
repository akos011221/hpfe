#include "flow_table.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"

/*
    Power of two check. Number is power of two if:
        - It is not zero
        - It has only one bit set
*/
static bool is_power_of_two(size_t x) {
    return x != 0 && (x & (x - 1)) == 0;
}

// Hashing function
static uint32_t fnv1a_u32(uint32_t h, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;

    // FNV-1a constants for 32-bit hash
    const uint32_t FNV_PRIME = 16777619u;

    for (size_t i = 0; i < len; i++) {
        h ^= (uint32_t)p[i];
        h *= FNV_PRIME;
    }
    return h;
}

static uint32_t flow_key_hash(const flow_key_t *k) {
    // Start offset basis (FNV-1a convention)
    uint32_t h = 2166136261u;

    // Field-by-field hashing to avoid padding hashing
    // (same flow can generate different hashes due to the padding)
    h = fnv1a_u32(h, &k->src_ip, sizeof(k->src_ip));
    h = fnv1a_u32(h, &k->dst_ip, sizeof(k->dst_ip));
    h = fnv1a_u32(h, &k->src_port, sizeof(k->src_port));
    h = fnv1a_u32(h, &k->dst_port, sizeof(k->dst_port));
    h = fnv1a_u32(h, &k->protocol, sizeof(k->protocol));

    return h;
}

static bool flow_key_equal(const flow_key_t *k1, const flow_key_t *k2) {
    return k1->src_ip == k2->src_ip && k1->dst_ip == k2->dst_ip && k1->src_port == k2->src_port &&
           k1->dst_port == k2->dst_port && k1->protocol == k2->protocol;
}

int flow_table_init(flow_table_t *t, size_t capacity) {
    if (!t) return -1;
    if (!is_power_of_two(capacity)) return -1;

    // calloc is used to zero out all the memory to make sure used=false
    flow_entry_t *arr = (flow_entry_t *)calloc(capacity, sizeof(flow_entry_t));
    if (!arr) return -1;

    t->entries = arr;
    t->capacity = capacity;
    t->size = 0;
    return 0;
}

void flow_table_destroy(flow_table_t *t) {
    if (!t) return;
    free(t->entries);
    t->entries = NULL;
    t->capacity = 0;
    t->size = 0;
}

int flow_table_put(flow_table_t *t, const flow_key_t *k, const flow_action_t *a) {
    if (!t || !k || !a) return -1;
    if (t->size >= t->capacity) return -1; // table is full

    uint32_t h = flow_key_hash(k);

    size_t mask = t->capacity - 1;
    size_t idx = (size_t)h & mask;

    /*
        Linear probing algorithm:
            - If the slot is empty, insert the entry
            - If the slot is occupied, check if the key matches
                - If it matches, update the action
                - If it doesn't match, move to the next slot
    */

    for (size_t probe = 0; probe < t->capacity; probe++) {
        flow_entry_t *e = &t->entries[idx];

        if (!e->used) {
            // Empty slot
            e->used = true;
            e->key = *k;    // struct copy
            e->action = *a; // struct copy
            t->size++;
            return 0;
        }

        if (flow_key_equal(&e->key, k)) {
            // Existing key, update action
            e->action = *a;
            return 0;
        }

        // Move to next slot
        idx = (idx + 1) & mask;
    }

    return -1;
}

bool flow_table_get(const flow_table_t *t, const flow_key_t *k, flow_action_t *out_a) {
    if (!t || !t->entries || !k) return false;

    uint32_t h = flow_key_hash(k);
    size_t mask = t->capacity - 1;
    size_t idx = (size_t)h & mask;

    for (size_t probe = 0; probe < t->capacity; probe++) {
        const flow_entry_t *e = &t->entries[idx];

        if (!e->used) {
            // Empty slot. Key can't be further, because insert
            // would have stopped at the 1st empty slot.
            return false;
        }

        if (flow_key_equal(&e->key, k)) {
            if (out_a) {
                *out_a = e->action;
            }
            return true;
        }

        idx = (idx + 1) & mask;
    }

    return false;
}