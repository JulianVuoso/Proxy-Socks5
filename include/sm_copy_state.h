#ifndef SM_COPY_STATE_H_4725792dc78436932378358825185b91959bbf5d
#define SM_COPY_STATE_H_4725792dc78436932378358825185b91959bbf5d

#include "buffer.h"
#include "selector.h"
#include "ettercap.h"


// COPY
typedef struct copy_st {
    buffer * cli_to_or_buf, * or_to_cli_buf;
    uint8_t cli_to_or_eof, or_to_cli_eof;

    bool sniffed;
    ettercap_parser ett_parser;
} copy_st;

void copy_init(const unsigned state, struct selector_key *key);
unsigned copy_read(struct selector_key * key);
unsigned copy_write(struct selector_key * key);
void copy_close(const unsigned state, struct selector_key *key);

#endif