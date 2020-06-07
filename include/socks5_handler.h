#ifndef SOCKS5_HANDLER_H_5682710912d2e501d7ab8a04f1fd4b5705cd4e81
#define SOCKS5_HANDLER_H_5682710912d2e501d7ab8a04f1fd4b5705cd4e81

#include "selector.h"

void socks5_read(selector_key * key);
void socks5_write(selector_key * key);
void socks5_block(selector_key * key);
void socks5_close(selector_key * key);

static const fd_handler socks5_handler = {
    .handle_read = socks5_read,
    .handle_write = socks5_write,
    .handle_block = socks5_block,
    .handle_close = socks5_close,
};

#endif