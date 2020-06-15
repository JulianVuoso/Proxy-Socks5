#ifndef SM_REQUEST_STATE_H_da39a3ee5e6b4b0d3255bfef95601890afd80709
#define SM_REQUEST_STATE_H_da39a3ee5e6b4b0d3255bfef95601890afd80709

#include "request.h"
#include "selector.h"

// REQUEST_READ, REQUEST_SOLVE, REQUEST_CONNECT y REQUEST_WRITE
typedef struct request_st {
    buffer * read_buf, * write_buf;
    struct request_parser parser;
    uint8_t reply_code;
    struct addrinfo * current;
} request_st;

void request_read_init(const unsigned state, struct selector_key *key);
unsigned request_read(struct selector_key *key);
void request_read_close(const unsigned state, struct selector_key *key);

unsigned request_process(struct selector_key *key);
unsigned request_connect(struct selector_key *key);
unsigned request_solve_block(struct selector_key *key);

unsigned request_connect_write(struct selector_key *key);

void request_write_init(const unsigned state, struct selector_key *key);
unsigned request_write(struct selector_key *key);
void request_close(const unsigned state, struct selector_key *key);

#endif