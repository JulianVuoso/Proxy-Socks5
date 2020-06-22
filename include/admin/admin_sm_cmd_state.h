#ifndef ADMIN_SM_CMD_STATE_H_ec58a696f3335b0ee9d399f70569d6a699db2510
#define ADMIN_SM_CMD_STATE_H_ec58a696f3335b0ee9d399f70569d6a699db2510

#include "admin.h"
#include "selector.h"

// negot_READ, negot_SOLVE, negot_CONNECT y negot_WRITE
typedef struct admin_cmd_st {
    buffer * read_buf, * write_buf;
    admin_parser parser;
    struct admin_data_word reply_word;
    bool marshall_error;
} admin_cmd_st;

unsigned admin_cmd_process(struct selector_key *key);

void admin_cmd_init(const unsigned state, struct selector_key *key);
void admin_cmd_close(const unsigned state, struct selector_key *key);

unsigned admin_cmd_read(struct selector_key *key);
unsigned admin_cmd_write(struct selector_key *key);

#endif