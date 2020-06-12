#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "socks5mt.h"
#include "negotiation.h"
#include "socks5_handler.h"

void negot_read_init(const unsigned state, struct selector_key *key) {
    struct negot_st * st = &ATTACHMENT(key)->client.negot;
    st->read_buf = &(ATTACHMENT(key)->read_buffer);
    st->write_buf = &(ATTACHMENT(key)->write_buffer);
    negot_parser_init(&st->parser);
}

unsigned negot_read(struct selector_key *key) {
    struct negot_st * st_vars = &ATTACHMENT(key)->client.negot;
    unsigned ret = NEGOT_READ;
    bool errored = false;
    size_t nbytes;
    uint8_t * buf_write_ptr = buffer_write_ptr(st_vars->read_buf, &nbytes);
    ssize_t n = recv(key->fd, buf_write_ptr, nbytes, 0);

    if (n > 0) {
        buffer_write_adv(st_vars->read_buf, n);
        const enum negot_state st = negot_consume(st_vars->read_buf, &st_vars->parser, &errored);
        if (negot_is_done(st, 0) && !errored) { // TODO: check if errored va en la condicion
            if (selector_set_interest_key(key, OP_WRITE) == SELECTOR_SUCCESS) {
                ret = negot_process(st_vars);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return errored ? ERROR : ret;
}

unsigned negot_process(const struct negot_st * st_vars) {
    unsigned ret = NEGOT_WRITE;
    if (negot_marshall(st_vars->write_buf, st_vars->reply_code) < 0)
        ret = ERROR;
    return ret;
}

void negot_read_close(const unsigned state, struct selector_key *key) {
    /* Do nothing */
}

static unsigned try_jump_negot_write(struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct negot_st * st_vars = &sock->client.negot;
    /* VER SI VA ESTO, PARA EL negot_MARSHALL */
    struct sockaddr client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    if (getsockname(sock->client_fd, &client_addr, &client_addr_len) < 0) {
        return ERROR;
    }
    
    struct sockaddr_in6 * client_addr_ipv6 = (struct sockaddr_in6 *) &client_addr;
    //uint8_t * ipv6 = (uint8_t *) &client_addr_ipv6->sin6_addr;
    //uint16_t port = ntohs(client_addr_ipv6->sin6_port);
    if (negot_marshall(st_vars->write_buf, st_vars->reply_code) < 0) {
        return ERROR;
    }
    return NEGOT_WRITE;
}

void negot_write_init(const unsigned state, struct selector_key *key) {
    /* Do nothing */
}

unsigned negot_write(struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
    /* Reviso que haya sido por client_fd, no deberia ser por otra cosa */
    if (key->fd != sock->client_fd) {
        abort();
    }
    struct negot_st * st_vars = &ATTACHMENT(key)->client.negot;
    unsigned ret = NEGOT_WRITE;
    size_t nbytes;
    uint8_t * buf_read_ptr = buffer_read_ptr(st_vars->write_buf, &nbytes);
    ssize_t n = send(key->fd, buf_read_ptr, nbytes, 0);

    if (n > 0) {
        buffer_read_adv(st_vars->write_buf, n);
        if (!buffer_can_read(st_vars->write_buf)) { // Termine de enviar el mensaje
            if (st_vars->reply_code == NEGOT_RESPONSE_SUCCESS) {
                /** TODO: Ver si esta bien habilitar el interes de lectura del origin_server  */
                if (selector_set_interest_key(key, OP_READ) == SELECTOR_SUCCESS) {
                    ret = REQUEST_READ;   // TODO: Cambiar a quien siga -> ESTA BIEN REQ?
                } else {
                    ret = ERROR;
                }
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return ret;
}

void negot_write_close(const unsigned state, struct selector_key *key) {
    struct negot_st * st = &ATTACHMENT(key)->client.negot;
    negot_parser_close(&st->parser);
}

