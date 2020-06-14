#include "socks5mt.h"

void do_before_error(struct selector_key * key) {
    unsigned state = ATTACHMENT(key)->stm.current->state;
    switch (state)
    {
    case REQUEST_READ:
        request_close(state, key);
        break;
    default:
        break;
    }
}