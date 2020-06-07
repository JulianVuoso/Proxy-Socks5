#include <stdlib.h>
#include "socks5mt.h"

void copy_init(const unsigned state, struct selector_key *key) {
    struct copy_st * st = &ATTACHMENT(key)->client.copy;
    st->cli_to_or_buf = &(ATTACHMENT(key)->read_buffer);
    st->or_to_cli_buf = &(ATTACHMENT(key)->write_buffer);
}

static unsigned try_jump_done(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    unsigned ret = DONE;

    if (selector_set_interest(key->s, sock->client_fd, OP_NOOP) != SELECTOR_SUCCESS) {
        ret = ERROR;
    }
    if (selector_set_interest(key->s, sock->origin_fd, OP_NOOP) != SELECTOR_SUCCESS) {
        ret = ERROR;
    }
    return ret;
}

unsigned copy_read(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct copy_st * st_vars = &ATTACHMENT(key)->client.copy;
    unsigned ret = COPY;
    size_t nbytes;
    uint8_t * buf_write_ptr;
    ssize_t n;
    buffer * buff;
    int other_fd;
    if (key->fd == sock->client_fd) {
        /* Lectura del cliente */
        buff = st_vars->cli_to_or_buf;
        other_fd = sock->origin_fd;
    } else if (key->fd == sock->origin_fd) {
        /* Lectura del origin_server */
        buff = st_vars->or_to_cli_buf;
        other_fd = sock->client_fd;
    } else {
        /* Lectura de ?? */
        abort();
    }
    buf_write_ptr = buffer_write_ptr(buff, &nbytes);
    n = recv(key->fd, buf_write_ptr, nbytes, 0);
    if (n > 0) {
        buffer_write_adv(buff, n);
        fd_interest cur_int;
        if (!buffer_can_write(buff)) {
            /* Si tenia prendido OP_READ del fd actual, lo apago porque se lleno */
            if (selector_get_interest(key->s, key->fd, &cur_int) != SELECTOR_SUCCESS) {
                ret = ERROR;
            }
            if ((cur_int & OP_READ) != 0 && selector_set_interest(key->s, key->fd, cur_int - OP_READ) != SELECTOR_SUCCESS) {
                ret = ERROR;
            }
        }
        /* Si tenia apagado OP_WRITE del otro fd, lo prendo */
        if (selector_get_interest(key->s, other_fd, &cur_int) != SELECTOR_SUCCESS) {
            ret = ERROR;
        }
        if ((cur_int & OP_WRITE) == 0 && selector_set_interest(key->s, other_fd, cur_int | OP_WRITE) != SELECTOR_SUCCESS) {
            ret = ERROR;
        }
    } else if (n == 0) {
        /* Chequeo que no haya cometido un error en algun lugar */
        if (nbytes == 0) {
            abort();
        }
        /* Si el cliente cerro la conexion, DONE. Sino, ERROR */
        ret = (key->fd == sock->client_fd) ? try_jump_done(key) : ERROR;
    } else {
        ret = ERROR;
    }

    return ret;
}

unsigned copy_write(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct copy_st * st_vars = &ATTACHMENT(key)->client.copy;
    unsigned ret = COPY;
    size_t nbytes;
    uint8_t * buf_read_ptr;
    ssize_t n;
    buffer * buff;
    int other_fd;
    if (key->fd == sock->client_fd) {
        /* Escritura del cliente */
        buff = st_vars->or_to_cli_buf;
        other_fd = sock->origin_fd;
    } else if (key->fd == sock->origin_fd) {
        /* Escritura del origin_server */
        buff = st_vars->cli_to_or_buf;
        other_fd = sock->client_fd;
    } else {
        /* Lectura de ?? */
        abort();
    }
    buf_read_ptr = buffer_read_ptr(buff, &nbytes);
    n = send(key->fd, buf_read_ptr, nbytes, 0);
    if (n > 0) {
        buffer_read_adv(buff, n);
        fd_interest cur_int;
        if (!buffer_can_read(buff)) {
            /* Si tenia prendido OP_WRITE del fd actual, lo apago porque se lleno */
            if (selector_get_interest(key->s, key->fd, &cur_int) != SELECTOR_SUCCESS) {
                ret = ERROR;
            }
            if ((cur_int & OP_WRITE) != 0 && selector_set_interest(key->s, key->fd, cur_int - OP_WRITE) != SELECTOR_SUCCESS) {
                ret = ERROR;
            }
        }
        /* Si tenia apagado OP_READ del otro fd, lo prendo */
        if (selector_get_interest(key->s, other_fd, &cur_int) != SELECTOR_SUCCESS) {
            ret = ERROR;
        }
        if ((cur_int & OP_READ) == 0 && selector_set_interest(key->s, other_fd, cur_int | OP_READ) != SELECTOR_SUCCESS) {
            ret = ERROR;
        }
        /* Si le escribi al origin server y tengo espacio de escritura en el buffer or_to_cli_buf
        ** me suscribo a la lectura del origin server */
        if (key->fd == sock->origin_fd && buffer_can_write(st_vars->or_to_cli_buf)) {
            /* Si tenia apagado OP_READ del origin_fd, lo prendo */
            if (selector_get_interest(key->s, sock->origin_fd, &cur_int) != SELECTOR_SUCCESS) {
                ret = ERROR;
            }
            if ((cur_int & OP_READ) == 0 && selector_set_interest(key->s, sock->origin_fd, cur_int | OP_READ) != SELECTOR_SUCCESS) {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return ret;
}

