#include <string.h>
//#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "socks5mt.h"
#include "negotiation.h"
// #include "socks5_handler.h"

#include "logger.h"

void negot_read_init(const unsigned state, struct selector_key *key) {
    struct negot_st * st = &ATTACHMENT(key)->client.negot;
    st->read_buf = &(ATTACHMENT(key)->read_buffer);
    st->write_buf = &(ATTACHMENT(key)->write_buffer);
    st->reply_code = NEGOT_RESPONSE_ERROR;
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
        if (negot_is_done(st, 0)) {
            if (selector_set_interest_key(key, OP_WRITE) == SELECTOR_SUCCESS) {
                ret = negot_process(key);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    // return errored ? ERROR : ret;
    return ret;
}

void negot_read_close(const unsigned state, struct selector_key *key) {
    struct negot_st * st = &ATTACHMENT(key)->client.negot;
    negot_parser_close(&st->parser);
}

unsigned negot_process(struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct negot_st * st_vars = &sock->client.negot;
    
    if (st_vars->parser.username == NULL || st_vars->parser.password == NULL) {
        st_vars->reply_code = NEGOT_RESPONSE_ERROR;
    } else {
        st_vars->reply_code = authenticate(st_vars->parser.username->uname, st_vars->parser.password->passwd);
        sock->username = calloc(st_vars->parser.username->ulen + 1, sizeof(*sock->username));
        if (sock->username == NULL) {
            st_vars->reply_code = NEGOT_RESPONSE_ERROR;
        } else {
            memcpy(sock->username, st_vars->parser.username->uname, st_vars->parser.username->ulen);
            sock->username_length = st_vars->parser.username->ulen;
        }
    }
    
    if (negot_marshall(st_vars->write_buf, st_vars->reply_code) < 0)
        return ERROR;   /** TODO: No deberia ser NEGOT_RESPONSE_ERROR? */
    
    return NEGOT_WRITE;
}

void negot_write_init(const unsigned state, struct selector_key *key) {
    /* Do nothing */
}

unsigned negot_write(struct selector_key *key) {
    struct negot_st * st_vars = &ATTACHMENT(key)->client.negot;
    unsigned ret = NEGOT_WRITE;
    size_t nbytes;
    uint8_t * buf_read_ptr = buffer_read_ptr(st_vars->write_buf, &nbytes);
    ssize_t n = send(key->fd, buf_read_ptr, nbytes, 0);

    if (n > 0) {
        buffer_read_adv(st_vars->write_buf, n);
        if (!buffer_can_read(st_vars->write_buf)) { // Termine de enviar el mensaje
            if (st_vars->reply_code == NEGOT_RESPONSE_SUCCESS) {
                if (selector_set_interest_key(key, OP_READ) == SELECTOR_SUCCESS) {
                    ret = REQUEST_READ;
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
    /* Do nothing */
}

