#include "socks5mt.h"

void do_before_error(struct selector_key * key) {
    unsigned state = ATTACHMENT(key)->stm.current->state;
    switch (state)
    {
    case NEGOT_READ:
        negot_read_close(state, key);
        break;
    case REQUEST_READ:
    case DNS_CONNECT:
    case DNS_WRITE:
    case DNS_READ:
    case DNS_SOLVE_BLK:
    case REQUEST_CONNECT:
    case REQUEST_WRITE:
        request_close(state, key);
        break;
    case COPY:
        copy_close(state, key);
        break;
    default:
        break;
    }
}