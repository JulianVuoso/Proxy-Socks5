#include <netdb.h>

#include "socks5mt.h"
#include "logger.h"

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

unsigned do_when_timeout(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    unsigned state = sock->stm.current->state;
    int * fd;
    unsigned (*next) (selector_key *);
    switch (state)
    {
        case REQUEST_CONNECT:
            fd = &(sock->origin_fd);
            sock->client.request.reply_code = REQUEST_RESPONSE_HOST_UNREACH;
            sock->client.request.current = sock->client.request.current->ai_next;
            /* Intento conectarme al siguiente */
            next = request_connect;
            break;
        case DNS_CONNECT:
            fd = &(sock->client.request.doh_fd);
            /* Defaulteo a getaddrinfo */
            next = prepare_blocking_doh;
            break;
        default:
            return state;
    }
    /* Desregistro el fd y lo cierro */
    if (selector_unregister_fd(key->s, *fd) != SELECTOR_SUCCESS) {
        logger_log(DEBUG, "failed selector\n");
        do_before_error(key);
        return ERROR;
    }
    close(*fd);
    *fd = -1;
    logger_log(DEBUG, "Connect failed because of timeout.\n");
    return next(key);
}