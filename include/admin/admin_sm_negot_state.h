#ifndef ADMIN_SM_NEGOT_STATE_H_a25312899308ee3956df80eb11d735f523134980
#define ADMIN_SM_NEGOT_STATE_H_a25312899308ee3956df80eb11d735f523134980

#include "negotiation.h"
#include "selector.h"

// ADMIN_NEGOT_READ y ADMIN_NEGOT_WRITE
typedef struct admin_negot_st {
    buffer * read_buf, * write_buf;
    struct negot_parser parser;
    uint8_t reply_code;
} admin_negot_st;

unsigned admin_negot_process(struct selector_key *key);

void admin_negot_read_init(const unsigned state, struct selector_key *key);
unsigned admin_negot_read(struct selector_key *key);
void admin_negot_read_close(const unsigned state, struct selector_key *key);

void admin_negot_write_init(const unsigned state, struct selector_key *key);
unsigned admin_negot_write(struct selector_key *key);
void admin_negot_write_close(const unsigned state, struct selector_key *key);

#endif