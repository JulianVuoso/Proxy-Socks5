#ifndef SM_NEGOT_STATE_H_5601890afd80709
#define SM_NEGOT_STATE_H_5601890afd80709

#include "negotiation.h"
#include "selector.h"

// negot_READ, negot_SOLVE, negot_CONNECT y negot_WRITE
typedef struct negot_st {
    buffer * read_buf, * write_buf;
    struct negot_parser parser;
    uint8_t reply_code;
} negot_st;

unsigned negot_process(struct selector_key *key);

void negot_read_init(const unsigned state, struct selector_key *key);
unsigned negot_read(struct selector_key *key);
void negot_read_close(const unsigned state, struct selector_key *key);

void negot_write_init(const unsigned state, struct selector_key *key);
unsigned negot_write(struct selector_key *key);
void negot_write_close(const unsigned state, struct selector_key *key);

#endif