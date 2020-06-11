#ifndef SM_COPY_STATE_H_4725792dc78436932378358825185b91959bbf5d
#define SM_COPY_STATE_H_4725792dc78436932378358825185b91959bbf5d

#include <stdbool.h>
#include "buffer.h"
#include "selector.h"

// COPY
typedef struct copy_st {
    buffer * cli_to_or_buf, * or_to_cli_buf;
    bool cli_to_or_eof, or_to_cli_eof;
} copy_st;

void copy_init(const unsigned state, struct selector_key *key);
unsigned copy_read(struct selector_key * key);
unsigned copy_write(struct selector_key * key);

#endif