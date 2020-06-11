#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>

#include "socks5mt.h"
#include "request.h"
#include "socks5_handler.h"

void request_read_init(const unsigned state, struct selector_key *key) {
    struct request_st * st = &ATTACHMENT(key)->client.request;
    st->read_buf = &(ATTACHMENT(key)->read_buffer);
    st->write_buf = &(ATTACHMENT(key)->write_buffer);
    request_parser_init(&st->parser);
}

unsigned request_read(struct selector_key *key) {
    struct request_st * st_vars = &ATTACHMENT(key)->client.request;
    unsigned ret = REQUEST_READ;
    bool errored = false;
    size_t nbytes;
    uint8_t * buf_write_ptr = buffer_write_ptr(st_vars->read_buf, &nbytes);
    ssize_t n = recv(key->fd, buf_write_ptr, nbytes, 0);

    if (n > 0) {
        buffer_write_adv(st_vars->read_buf, n);
        const enum request_state st = request_consume(st_vars->read_buf, &st_vars->parser, &errored);
        if (request_is_done(st, 0) && !errored) { // TODO: check if errored va en la condicion
            if (selector_set_interest_key(key, OP_NOOP) == SELECTOR_SUCCESS) {
                ret = request_process(key);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return errored ? ERROR : ret;
}

void request_read_close(const unsigned state, struct selector_key *key) {
    /* Do nothing */
}

static struct sockaddr_in 
get_origin_addr_ipv4(const struct destination * dest) {
    struct sockaddr_in origin_addr;
    memset(&origin_addr, 0, sizeof(origin_addr));
    origin_addr.sin_family = AF_INET;
    memcpy(&origin_addr.sin_addr, dest->address, dest->address_length);
    origin_addr.sin_port = htons(dest->port);
    return origin_addr;
}

static struct sockaddr_in6 
get_origin_addr_ipv6(const struct destination * dest) {
    struct sockaddr_in6 origin_addr6;
    memset(&origin_addr6, 0, sizeof(origin_addr6));
    origin_addr6.sin6_family = AF_INET6;
    memcpy(&origin_addr6.sin6_addr, dest->address, dest->address_length);
    origin_addr6.sin6_port = htons(dest->port);
    return origin_addr6;
}

unsigned request_process(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct destination * dest = sock->client.request.parser.dest;
    
    switch (dest->address_type)
    {
        case address_fqdn:
            return REQUEST_SOLVE;
        case address_ipv4:
            sock->origin_domain = AF_INET;
            struct sockaddr_in origin_addr = get_origin_addr_ipv4(dest);
            memcpy(&(sock->origin_addr), &origin_addr, sizeof(origin_addr));
            sock->origin_addr_len = sizeof(sock->origin_addr); // Si no funca, poner de origin_addr
            break;
        case address_ipv6:
            sock->origin_domain = AF_INET6;
            struct sockaddr_in6 origin_addr6 = get_origin_addr_ipv6(dest);
            memcpy(&(sock->origin_addr), &origin_addr6, sizeof(origin_addr6));
            sock->origin_addr_len = sizeof(sock->origin_addr); // Si no funca, poner de origin_addr6
            break;
        default:
            // Unknown Address Type
            abort();
            break;
    }
    return request_connect(key);
}

static unsigned try_jump_request_write(struct selector_key *key) {
    // struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st_vars = &ATTACHMENT(key)->client.request;
    /* VER SI VA ESTO, PARA EL REQUEST_MARSHALL */
    /* struct sockaddr client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    if (getsockname(sock->client_fd, &client_addr, &client_addr_len) < 0) {
        return ERROR;
    }
    if (client_addr.sa_family == AF_INET) {
        struct sockaddr_in * client_addr_ipv4 = (struct sockaddr_in *) &client_addr;
        uint8_t * ipv4 = (uint8_t *) &client_addr_ipv4->sin_addr;
        uint16_t port = ntohs(client_addr_ipv4->sin_port);
        if (request_marshall(st_vars->write_buf, st_vars->reply_code, address_ipv4, ipv4, port) < 0) {
            return ERROR;
        }
        
    } else if (client_addr.sa_family == AF_INET6) {
        struct sockaddr_in6 * client_addr_ipv6 = (struct sockaddr_in6 *) &client_addr;
        uint8_t * ipv6 = (uint8_t *) &client_addr_ipv6->sin6_addr;
        uint16_t port = ntohs(client_addr_ipv6->sin6_port);
        if (request_marshall(st_vars->write_buf, st_vars->reply_code, address_ipv6, ipv6, port) < 0) {
            return ERROR;
        }
    } */
    if (request_marshall(st_vars->write_buf, st_vars->reply_code, st_vars->parser.dest->address_type) < 0) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

unsigned request_connect(struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
    if((sock->origin_fd = socket(sock->origin_domain, SOCK_STREAM, 0)) < 0) {
        goto errors;
    }
    /* Agrego referencia en el sock, se agrega un fd */
    sock->references += 1;
    if (selector_fd_set_nio(sock->origin_fd) < 0) {
        goto errors;
    }
    /* Connecting to origin_server */
    if (connect(sock->origin_fd, (const struct sockaddr *) &sock->origin_addr, sock->origin_addr_len) < 0) {
        if (errno == EINPROGRESS) {
            /* Espero a poder escribirle al origin_server para determinar si me pude conectar */
            if (selector_register(key->s, sock->origin_fd, &socks5_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
                goto errors;
            }
            return REQUEST_CONNECT;
        } else {
            goto errors;
        }
    }
    /* Si me conecte, por ahora no necesito esperar nada de origin, voy a escribirle a client */
    if (selector_register(key->s, sock->origin_fd, &socks5_handler, OP_NOOP, key->data) != SELECTOR_SUCCESS) {
        goto errors;
    }
    if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        goto errors;
    }

    sock->client.request.reply_code = REQUEST_RESPONSE_SUCCESS;
    return try_jump_request_write(key);

errors:
    if (sock->origin_fd >= 0) {
        close(sock->origin_fd);
    }
    return ERROR;
}

unsigned request_connect_write(struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
    /* Reviso que haya sido por origin_fd, no deberia ser por otra cosa */
    if (key->fd != sock->origin_fd) {
        abort();
    }
    unsigned optval = 1, optlen = sizeof(optval);
    if (getsockopt(sock->origin_fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0
            || optval != 0) {
        return ERROR;
    }
    /* Si me conecte, por ahora no necesito esperar nada de origin, voy a escribirle a client */
    if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    if (selector_set_interest(key->s, sock->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    sock->client.request.reply_code = REQUEST_RESPONSE_SUCCESS;
    return try_jump_request_write(key);
}

void request_write_init(const unsigned state, struct selector_key *key) {
    /* Do nothing */
}

unsigned request_write(struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
    /* Reviso que haya sido por client_fd, no deberia ser por otra cosa */
    if (key->fd != sock->client_fd) {
        abort();
    }

    struct request_st * st_vars = &sock->client.request;
    unsigned ret = REQUEST_WRITE;
    size_t nbytes;
    uint8_t * buf_read_ptr = buffer_read_ptr(st_vars->write_buf, &nbytes);
    ssize_t n = send(key->fd, buf_read_ptr, nbytes, 0);

    if (n > 0) {
        buffer_read_adv(st_vars->write_buf, n);
        if (!buffer_can_read(st_vars->write_buf)) { // Termine de enviar el mensaje
            if (st_vars->reply_code == REQUEST_RESPONSE_SUCCESS) {
                if (selector_set_interest(key->s, sock->client_fd, OP_READ) == SELECTOR_SUCCESS && 
                        selector_set_interest(key->s, sock->origin_fd, OP_READ) == SELECTOR_SUCCESS) {
                    ret = COPY;
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

void request_write_close(const unsigned state, struct selector_key *key) {
    struct request_st * st = &ATTACHMENT(key)->client.request;
    request_parser_close(&st->parser);
}

