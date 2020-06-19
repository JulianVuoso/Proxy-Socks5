#include "socks5mt.h"
#include "hello.h"
#include "logger.h"

static void
on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t * selected = p->data;
    // TODO: Change to SOCKS_HELLO_AUTHENTICATION_REQUIRED
    if (method == SOCKS_HELLO_AUTHENTICATION_REQUIRED) {
        *selected = method;
    }
}

void hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st * st = &ATTACHMENT(key)->client.hello;
    st->read_buf = &(ATTACHMENT(key)->read_buffer);
    st->write_buf = &(ATTACHMENT(key)->write_buffer);
    st->method = SOCKS_HELLO_NO_ACCEPTABLE_METHODS; // TODO: CHECK SI VA
    st->parser.data = &st->method;
    st->parser.on_authentication_method = on_hello_method;
    hello_parser_init(&st->parser);
}

unsigned hello_read(struct selector_key *key) {
    struct hello_st * st_vars = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_READ;
    bool errored = false;
    size_t nbytes;
    uint8_t * buf_write_ptr = buffer_write_ptr(st_vars->read_buf, &nbytes);
    ssize_t n = recv(key->fd, buf_write_ptr, nbytes, 0);

    if (n > 0) {
        buffer_write_adv(st_vars->read_buf, n);
        const enum hello_state st = hello_consume(st_vars->read_buf, &st_vars->parser, &errored);
        if (hello_is_done(st, 0)) {
            if (selector_set_interest_key(key, OP_WRITE) == SELECTOR_SUCCESS) {
                ret = hello_process(st_vars);
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

void hello_read_close(const unsigned state, struct selector_key *key) {
    struct hello_st * st = &ATTACHMENT(key)->client.hello;
    hello_parser_close(&st->parser);
}

unsigned hello_process(const struct hello_st * st_vars) {
    unsigned ret = HELLO_WRITE;
    uint8_t method = st_vars->method;
    if (hello_marshall(st_vars->write_buf, method) < 0) {
        ret = ERROR;
    }
    return ret;
}

void hello_write_init(const unsigned state, struct selector_key *key) {
    /* Do nothing */
}

unsigned hello_write(struct selector_key *key) {
    struct hello_st * st_vars = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_WRITE;
    size_t nbytes;
    uint8_t * buf_read_ptr = buffer_read_ptr(st_vars->write_buf, &nbytes);
    ssize_t n = send(key->fd, buf_read_ptr, nbytes, MSG_NOSIGNAL);

    if (n > 0) {
        buffer_read_adv(st_vars->write_buf, n);
        if (!buffer_can_read(st_vars->write_buf)) { // Termine de enviar el mensaje
            if (st_vars->method != SOCKS_HELLO_NO_ACCEPTABLE_METHODS) {
                logger_log(DEBUG, "Hello OK\n");
                if (selector_set_interest_key(key, OP_READ) == SELECTOR_SUCCESS) {
                    ret = NEGOT_READ; 
                } else {
                    ret = ERROR;
                }
            } else {
                logger_log(DEBUG, "Hello Failed\n");
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return ret;
}

void hello_write_close(const unsigned state, struct selector_key *key) {
    /* Do nothing */
}