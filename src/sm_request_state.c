#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <netdb.h>      // getaddrinfo
#include <stdio.h>

#include "socks5mt.h"
#include "request.h"
#include "socks5_handler.h"

void request_read_init(const unsigned state, struct selector_key *key) {
    struct request_st * st = &ATTACHMENT(key)->client.request;
    st->read_buf = &(ATTACHMENT(key)->read_buffer);
    st->write_buf = &(ATTACHMENT(key)->write_buffer);
    request_parser_init(&st->parser);
    st->current = NULL;
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

static void * request_solve_blocking(void * args) {
    struct selector_key * key = (struct selector_key *) args;
    struct socks5 * sock = ATTACHMENT(key);
    struct destination * dest = sock->client.request.parser.dest;

    pthread_detach(pthread_self());
    const struct addrinfo hints = {
        .ai_flags       = AI_PASSIVE,   /* For wildcarp IP address */
        .ai_family      = AF_UNSPEC,    /* IPv4 o IPv6 */
        .ai_socktype    = SOCK_STREAM,  /* Datagram socket */
        .ai_protocol    = 0,            /* Any protocol */
        .ai_addr        = NULL,
        .ai_canonname   = NULL,
        .ai_next        = NULL,
    };
    
    char port[7];
    // snprintf(port, sizeof(port), "%d", ntohs(dest->port));
    snprintf(port, sizeof(port), "%d", dest->port);
    if (getaddrinfo((char *) dest->address, port, &hints, &sock->origin_resolution) != 0) {
        /* If getaddrinfo fails, freeaddrinfo and set res to NULL */
        freeaddrinfo(sock->origin_resolution);
        sock->origin_resolution = NULL;
    }

    selector_notify_block(key->s, key->fd);

    free(args);
    return 0;
}

static int set_origin_resolution(struct socks5 * sock, struct sockaddr * sock_address, int family, uint8_t length) {
    sock->origin_resolution = calloc(1, sizeof(*sock->origin_resolution));
    if (sock->origin_resolution == NULL) {
        return -1;
    }
    sock->origin_resolution->ai_family = family;
    /** TODO: freeaddrinfo is not freeing this malloc, do it manually  */
    sock->origin_resolution->ai_addr = malloc(length);
    if (sock->origin_resolution->ai_addr == NULL) {
        return -1;
    }
    memcpy(sock->origin_resolution->ai_addr, sock_address, length);
    sock->origin_resolution->ai_addrlen = length;
    sock->origin_resolution->ai_next = NULL;

    sock->origin_resolution->ai_socktype = SOCK_STREAM;
    sock->origin_resolution->ai_protocol = IPPROTO_TCP;

    sock->client.request.current = sock->origin_resolution;
    return 0;
}

unsigned request_process(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct destination * dest = sock->client.request.parser.dest;
    pthread_t thread_pid = 0;

    switch (dest->address_type)
    {
        case address_fqdn: {
            struct selector_key * key_param = malloc(sizeof(*key));
            if (key_param == NULL) {
                goto error;
            }
            memcpy(key_param, key, sizeof(*key_param));
            if (pthread_create(&thread_pid, 0, request_solve_blocking, key_param) != 0) {
                puts("failed thread creation\n");
                goto error;
            }
            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
                puts("failed selecto\n");
                goto error;
            }
            return REQUEST_SOLVE;
        } case address_ipv4: {
            // sock->origin_domain = AF_INET;
            struct sockaddr_in origin_addr = get_origin_addr_ipv4(dest);
            // memcpy(&(sock->origin_addr), &origin_addr, sizeof(origin_addr));
            // sock->origin_addr_len = sizeof(sock->origin_addr); // Si no funca, poner de origin_addr
            if (set_origin_resolution(sock, (struct sockaddr *) &origin_addr, AF_INET, sizeof(origin_addr)) < 0) {
                puts("failed malloc\n");
                goto error;
            }
            break;
        } case address_ipv6: {
            // sock->origin_domain = AF_INET6;
            struct sockaddr_in6 origin_addr6 = get_origin_addr_ipv6(dest);
            // memcpy(&(sock->origin_addr), &origin_addr6, sizeof(origin_addr6));
            // sock->origin_addr_len = sizeof(sock->origin_addr); // Si no funca, poner de origin_addr6
            
            if (set_origin_resolution(sock, (struct sockaddr *) &origin_addr6, AF_INET6, sizeof(origin_addr6)) < 0) {
                puts("failed malloc\n");
                goto error;
            }
            break;
        } default: {
            // Unknown Address Type
            abort();
            break;
        }
    }
    return request_connect(key);

error:
    if (thread_pid != 0) {
        pthread_cancel(thread_pid);
    }
    return ERROR;
}

unsigned request_solve_block(struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
    if (sock->origin_resolution == NULL) {
        puts("failed getaddrinfo\n");
        return ERROR;
    }
    sock->client.request.current = sock->origin_resolution;
    return request_connect(key);
}

static unsigned try_jump_request_write(struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
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
    if (selector_set_interest(key->s, sock->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        puts("failed selector\n");
        return ERROR;
    }
    if (request_marshall(st_vars->write_buf, st_vars->reply_code, 
            (sock->origin_domain == AF_INET) ? address_ipv4 : address_ipv6) < 0) {
        puts("failed request_marshall\n");
        return ERROR;
    }
    return REQUEST_WRITE;
}

enum connect_result {CON_OK, CON_ERROR, CON_INPROG};

static enum connect_result 
try_connect(struct selector_key * key, struct addrinfo * node) {
    struct socks5 * sock = ATTACHMENT(key);
    if((sock->origin_fd = socket(node->ai_family, node->ai_socktype, node->ai_protocol)) < 0) {
        puts("failed socket creation\n");
        goto errors;
    }
    /* Agrego referencia en el sock, se agrega un fd */
    sock->references += 1;
    if (selector_fd_set_nio(sock->origin_fd) < 0) {
        puts("failed selector set nio\n");
        goto errors;
    }
    /* Connecting to origin_server */
    if (connect(sock->origin_fd, node->ai_addr, node->ai_addrlen) < 0) {
        if (errno == EINPROGRESS) {
            puts("EINPROGRESS\n");
            /* Espero a poder escribirle al origin_server para determinar si me pude conectar */
            if (selector_register(key->s, sock->origin_fd, &socks5_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
                puts("failed selector\n");
                goto errors;
            }
            return CON_INPROG;
        } else {
            printf("\n\nError. errno message: %s\n\n", strerror(errno));
            goto errors;
        }
    }
    /* Si me conecte, por ahora no necesito esperar nada de origin, voy a escribirle a client */
    if (selector_register(key->s, sock->origin_fd, &socks5_handler, OP_NOOP, key->data) != SELECTOR_SUCCESS) {
        puts("failed selector\n");
        goto errors;
    }
    return CON_OK;
    // sock->client.request.reply_code = REQUEST_RESPONSE_SUCCESS;
    // return try_jump_request_write(key);

errors:
    if (sock->origin_fd >= 0) {
        close(sock->origin_fd);
        sock->origin_fd = -1;
        sock->references -= 1;
    }
    return CON_ERROR;
}

unsigned request_connect(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct addrinfo * node = sock->client.request.current;
    if (node == NULL) {
        puts("Empty current node\n");
        return ERROR;
    }
    enum connect_result res;
    do {
        res = try_connect(key, node);
    } while (res == CON_ERROR && (node = node->ai_next) != NULL);
    switch (res)
    {
        case CON_INPROG:
            return REQUEST_CONNECT;
        case CON_OK:
            memcpy(&(sock->origin_addr), node, sizeof(*node));
            sock->origin_addr_len = sizeof(*node);
            sock->origin_domain = node->ai_family;
            sock->client.request.reply_code = REQUEST_RESPONSE_SUCCESS;
            return try_jump_request_write(key);
        case CON_ERROR:
            /* Could not connect to any ip address */
            puts("could not connect to any ip\n");
            return ERROR;
        default:
            /* Invalid result */
            abort();
    }
}

// unsigned request_connect(struct selector_key *key) {
//     struct socks5 * sock = ATTACHMENT(key);
//     if((sock->origin_fd = socket(sock->origin_domain, SOCK_STREAM, 0)) < 0) {
//         goto errors;
//     }
//     /* Agrego referencia en el sock, se agrega un fd */
//     sock->references += 1;
//     if (selector_fd_set_nio(sock->origin_fd) < 0) {
//         goto errors;
//     }
//     /* Connecting to origin_server */
//     if (connect(sock->origin_fd, (const struct sockaddr *) &sock->origin_addr, sock->origin_addr_len) < 0) {
//         if (errno == EINPROGRESS) {
//             /* Espero a poder escribirle al origin_server para determinar si me pude conectar */
//             if (selector_register(key->s, sock->origin_fd, &socks5_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
//                 goto errors;
//             }
//             return REQUEST_CONNECT;
//         } else {
//             goto errors;
//         }
//     }
//     /* Si me conecte, por ahora no necesito esperar nada de origin, voy a escribirle a client */
//     if (selector_register(key->s, sock->origin_fd, &socks5_handler, OP_NOOP, key->data) != SELECTOR_SUCCESS) {
//         goto errors;
//     }
//     sock->client.request.reply_code = REQUEST_RESPONSE_SUCCESS;
//     return try_jump_request_write(key);

// errors:
//     if (sock->origin_fd >= 0) {
//         close(sock->origin_fd);
//     }
//     return ERROR;
// }

unsigned request_connect_write(struct selector_key *key) {
    puts("Gonna get SOL_SOCKET option");
    struct socks5 * sock = ATTACHMENT(key);
    struct addrinfo * node = sock->client.request.current;
    /* Reviso que haya sido por origin_fd, no deberia ser por otra cosa */
    if (key->fd != sock->origin_fd) {
        abort();
    }
    /* Si me conecte o no, por ahora no necesito esperar nada de origin, voy a escribirle a client */
    if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
        puts("failed selector\n");
        return ERROR;
    }
    unsigned optval = 1, optlen = sizeof(optval);
    if (getsockopt(sock->origin_fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0
            || optval != 0) {
        /* Avanzo al siguiente nodo e intento conectarme */
        puts("this one failed, go to next\n");
        node = node->ai_next;
        return request_connect(key);
    }
    memcpy(&(sock->origin_addr), node, sizeof(*node));
    sock->origin_addr_len = sizeof(*node);
    sock->origin_domain = node->ai_family;
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
                    puts("failed selector\n");
                    ret = ERROR;
                }
            } else {
                puts("reply code unsuccessfull\n");
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

/** TODO: WHEN ERROR, call this close ^ */