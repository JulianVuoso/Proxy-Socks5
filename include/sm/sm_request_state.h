#ifndef SM_REQUEST_STATE_H_da39a3ee5e6b4b0d3255bfef95601890afd80709
#define SM_REQUEST_STATE_H_da39a3ee5e6b4b0d3255bfef95601890afd80709

#include "request.h"
#include "selector.h"
#include "doh_answer_struct.h"

// REQUEST_READ, DNS_SOLVE_BLK, REQUEST_CONNECT y REQUEST_WRITE
typedef struct request_st {
    buffer * read_buf, * write_buf;
    /* Request states vars */
    struct request_parser parser;
    uint8_t reply_code;
    /* Connect states vars */
    int doh_fd;
    struct DOHQueryResSM doh_parser;

    struct addrinfo * current;
} request_st;

void request_read_init(const unsigned state, struct selector_key *key);
unsigned request_read(struct selector_key *key);
void request_read_close(const unsigned state, struct selector_key *key);

unsigned request_process(struct selector_key *key);
unsigned request_connect(struct selector_key *key);

unsigned request_connect_write(struct selector_key *key);

void request_write_init(const unsigned state, struct selector_key *key);
unsigned request_write(struct selector_key *key);
void request_close(const unsigned state, struct selector_key *key);

unsigned try_jump_request_write(struct selector_key *key);

#endif