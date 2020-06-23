#ifndef ADMIN_HANDLER_H_d4b994cb2a7aa3776545a53e53b0256b1a200396
#define ADMIN_HANDLER_H_d4b994cb2a7aa3776545a53e53b0256b1a200396

#include "selector.h"

void admin_read(selector_key * key);
void admin_write(selector_key * key);
void admin_block(selector_key * key);
void admin_close(selector_key * key);

static const fd_handler admin_handler = {
    .handle_read = admin_read,
    .handle_write = admin_write,
    .handle_block = admin_block,
    .handle_close = admin_close,
};

#endif