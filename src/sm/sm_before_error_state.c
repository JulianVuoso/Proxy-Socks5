#include "socks5mt.h"

void do_before_error(struct selector_key * key) {
    unsigned state = ATTACHMENT(key)->stm.current->state;
    switch (state)
    {
    case REQUEST_READ:
    case DNS_CONNECT:
    case DNS_WRITE:
    case DNS_READ:
    case DNS_SOLVE_BLK:
    case REQUEST_CONNECT:
        request_close(state, key);
        break;
    default:
        break;
    }
}