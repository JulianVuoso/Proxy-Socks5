#include <stdlib.h>
#include "socks5mt.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>

void copy_init(const unsigned state, struct selector_key *key) {
    struct copy_st * st = &ATTACHMENT(key)->client.copy;
    st->cli_to_or_buf = &(ATTACHMENT(key)->read_buffer);
    st->or_to_cli_buf = &(ATTACHMENT(key)->write_buffer);
    st->cli_to_or_eof = 0;
    st->or_to_cli_eof = 0;
}

static unsigned try_jump_done(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    unsigned ret = DONE;

    if (selector_set_interest(key->s, sock->client_fd, OP_NOOP) != SELECTOR_SUCCESS) {
        puts("failed selector\n");
        ret = ERROR;
    }
    if (selector_set_interest(key->s, sock->origin_fd, OP_NOOP) != SELECTOR_SUCCESS) {
        puts("failed selector\n");
        ret = ERROR;
    }
    puts("\nRequest resuelto correctamente");
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
    uint8_t * cur_eof, * other_eof;
    if (key->fd == sock->client_fd) {
        /* Lectura del cliente */
        buff = st_vars->cli_to_or_buf;
        other_fd = sock->origin_fd;
        cur_eof = &st_vars->cli_to_or_eof;
        other_eof = &st_vars->or_to_cli_eof;
    } else if (key->fd == sock->origin_fd) {
        /* Lectura del origin_server */
        buff = st_vars->or_to_cli_buf;
        other_fd = sock->client_fd;
        cur_eof = &st_vars->or_to_cli_eof;
        other_eof = &st_vars->cli_to_or_eof;
    } else {
        /* Lectura de ?? */
        abort();
    }
    buf_write_ptr = buffer_write_ptr(buff, &nbytes);
    n = recv(key->fd, buf_write_ptr, nbytes, 0);
    if (n > 0) {
        buffer_write_adv(buff, n);
        if (!buffer_can_write(buff)) {
            /* Si tenia prendido OP_READ del fd actual, lo apago porque se lleno */
            if (selector_remove_interest(key->s, key->fd, OP_READ) != SELECTOR_SUCCESS) {
                puts("failed selector\n");
                ret = ERROR;
            }
        }
        /* Si tenia apagado OP_WRITE del otro fd, lo prendo */
        if (selector_add_interest(key->s, other_fd, OP_WRITE) != SELECTOR_SUCCESS) {
            puts("failed selector\n");
            ret = ERROR;
        }
    } else if (n == 0) {
        /* Chequeo que no haya cometido un error en algun lugar */
        if (nbytes == 0) {
            abort();
        }
        /* Me desuscribo de lectura del fd actual */
        if (selector_remove_interest(key->s, key->fd, OP_READ) != SELECTOR_SUCCESS) {
            puts("failed selector\n");
            ret = ERROR;
        }
        (*cur_eof) += 1;
        /* Si consumieron todo lo que escribi en el buffer, mando EOF */
        if (!buffer_can_read(buff)) {
            (*other_eof) += 1;
            if (shutdown(other_fd, SHUT_WR) < 0) {
                puts("failed shutdown in read\n");
                printf("\n\nEOF curr: %d, EOF other: %d. \nError. errno %d message: %s\n\n", *cur_eof, *other_eof, errno, strerror(errno));
                ret = ERROR;
            }
        }
    } else {
        puts("recv error\n");
        printf("\n\nEOF curr: %d, EOF other: %d. \nError. errno %d message: %s\n\n", *cur_eof, *other_eof, errno, strerror(errno));
        ret = ERROR;
    }

    /* Si conte dos EOF por lado --> DONE */
    if (ret != ERROR && (*cur_eof) == 2 && (*other_eof) == 2) {
        ret = try_jump_done(key);
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
    uint8_t * cur_eof, * other_eof;
    if (key->fd == sock->client_fd) {
        /* Escritura del cliente */
        buff = st_vars->or_to_cli_buf;
        other_fd = sock->origin_fd;
        cur_eof = &st_vars->or_to_cli_eof;
        other_eof = &st_vars->cli_to_or_eof;
    } else if (key->fd == sock->origin_fd) {
        /* Escritura del origin_server */
        buff = st_vars->cli_to_or_buf;
        other_fd = sock->client_fd;
        cur_eof = &st_vars->cli_to_or_eof;
        other_eof = &st_vars->or_to_cli_eof;
    } else {
        /* Lectura de ?? */
        abort();
    }
    buf_read_ptr = buffer_read_ptr(buff, &nbytes);
    n = send(key->fd, buf_read_ptr, nbytes, 0);
    if (n > 0) {
        buffer_read_adv(buff, n);
        if (!buffer_can_read(buff)) {
            /* Si tenia prendido OP_WRITE del fd actual, lo apago porque se lleno */
            if (selector_remove_interest(key->s, key->fd, OP_WRITE) != SELECTOR_SUCCESS) {
                puts("failed selector\n");
                ret = ERROR;
            }
            /** TODO: CHECK SI ESTO VA BIEN  */
            if (*cur_eof) {
                (*other_eof) += 1;
                if (shutdown(key->fd, SHUT_WR) < 0) {
                    puts("failed shutdown in write\n");
                    printf("\n\nEOF curr: %d, EOF other: %d. \nError. errno %d message: %s\n\n", *cur_eof, *other_eof, errno, strerror(errno));
                    ret = ERROR;
                }
            }
        }
        /* Si no me cerraron conexion y tenia apagado OP_READ del otro fd, lo prendo */
        if (!(*cur_eof) && selector_add_interest(key->s, other_fd, OP_READ) != SELECTOR_SUCCESS) {
            puts("failed selector\n");
            ret = ERROR;
        }
    } else {
        puts("failed send\n");
        ret = ERROR;
    }

    /* Si conte dos EOF por lado --> DONE */
    if (ret != ERROR && (*cur_eof) == 2 && (*other_eof) == 2) {
        ret = try_jump_done(key);
    }
    return ret;
}
