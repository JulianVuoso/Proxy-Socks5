#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <netdb.h>      // getaddrinfo
#include <stdio.h>
#include <time.h>

#include "logger.h"
#include "netutils.h"
#include "sm_actions.h"

#include "socks5mt.h"
#include "request.h"
#include "socks5_handler.h"
#include "dohParser.h"

static void access_log(struct socks5 * sock);


void request_read_init(const unsigned state, struct selector_key *key) {
    struct request_st * st = &ATTACHMENT(key)->client.request;
    st->read_buf = &(ATTACHMENT(key)->read_buffer);
    st->write_buf = &(ATTACHMENT(key)->write_buffer);
    request_parser_init(&st->parser);
    st->current = NULL;
    st->reply_code = REQUEST_RESPONSE_GEN_SOCK_FAIL;
    st->doh_fd = -1;
}

unsigned request_read(struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st_vars = &sock->client.request;
    unsigned ret = REQUEST_READ;
    bool errored = false;
    size_t nbytes;
    uint8_t * buf_write_ptr = buffer_write_ptr(st_vars->read_buf, &nbytes);
    ssize_t n = recv(key->fd, buf_write_ptr, nbytes, 0);

    if (n > 0) {
        buffer_write_adv(st_vars->read_buf, n);
        const enum request_state st = request_consume(st_vars->read_buf, &st_vars->parser, &errored);
        if (request_is_done(st, 0)) {
            if (errored) {
                st_vars->reply_code = request_reply_code(&st_vars->parser);
                logger_log(DEBUG, "Error in request parser. Message: %s\n", request_error_description(&st_vars->parser));
                sock->origin_domain = (st_vars->parser.dest != NULL && st_vars->parser.dest->address_type == address_ipv6) ? AF_INET6 : AF_INET;
                ret = try_jump_request_write(key);
            } else if (selector_set_interest_key(key, OP_NOOP) == SELECTOR_SUCCESS) {
                ret = request_process(key);
            } else {
                do_before_error(key);
                ret = ERROR;
            }
        }
    } else {
        do_before_error(key);
        ret = ERROR;
    }

    // return errored ? ERROR : ret;
    return ret;
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

static int set_origin_resolution(struct socks5 * sock, struct sockaddr * sock_address, int family, uint8_t length) {
    sock->origin_resolution = calloc(1, sizeof(*sock->origin_resolution));
    if (sock->origin_resolution == NULL) {
        return -1;
    }
    sock->origin_resolution->ai_family = family;
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
    struct request_st * st_vars = &sock->client.request;
    struct destination * dest = st_vars->parser.dest;
    // pthread_t thread_pid = 0;

    switch (dest->address_type)
    {
        case address_fqdn: {
            sock->fqdn = calloc(dest->address_length + 1, sizeof(*sock->fqdn));
            if (sock->fqdn == NULL) {
                goto error;
            }
            strncpy(sock->fqdn, (char *) dest->address, dest->address_length);
            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
                logger_log(DEBUG, "failed selector\n");
                goto error;
            }
            return start_doh_connect(key);

            /* struct selector_key * key_param = malloc(sizeof(*key));
            if (key_param == NULL) {
                goto error;
            }
            memcpy(key_param, key, sizeof(*key_param));
            if (pthread_create(&thread_pid, 0, request_solve_blocking, key_param) != 0) {
                logger_log(DEBUG, "failed thread creation\n");
                goto error;
            }
            return DNS_SOLVE_BLK; */
        } case address_ipv4: {
            // sock->origin_domain = AF_INET;
            struct sockaddr_in origin_addr = get_origin_addr_ipv4(dest);
            // memcpy(&(sock->origin_addr), &origin_addr, sizeof(origin_addr));
            // sock->origin_addr_len = sizeof(sock->origin_addr); // Si no funca, poner de origin_addr
            if (set_origin_resolution(sock, (struct sockaddr *) &origin_addr, AF_INET, sizeof(origin_addr)) < 0) {
                logger_log(DEBUG, "failed malloc\n");
                goto error;
            }
            break;
        } case address_ipv6: {
            // sock->origin_domain = AF_INET6;
            struct sockaddr_in6 origin_addr6 = get_origin_addr_ipv6(dest);
            // memcpy(&(sock->origin_addr), &origin_addr6, sizeof(origin_addr6));
            // sock->origin_addr_len = sizeof(sock->origin_addr); // Si no funca, poner de origin_addr6
            
            if (set_origin_resolution(sock, (struct sockaddr *) &origin_addr6, AF_INET6, sizeof(origin_addr6)) < 0) {
                logger_log(DEBUG, "failed malloc\n");
                goto error;
            }
            break;
        } default: {
            // Unknown Address Type
            abort();
        }
    }
    return request_connect(key);

error:
    /* if (thread_pid != 0) {
        pthread_cancel(thread_pid);
    } */
    st_vars->reply_code = REQUEST_RESPONSE_GEN_SOCK_FAIL;
    logger_log(DEBUG, "Error in request processing.\n");
    sock->origin_domain = (st_vars->parser.dest != NULL && st_vars->parser.dest->address_type == address_ipv6) ? AF_INET6 : AF_INET;
    return try_jump_request_write(key);
}

unsigned try_jump_request_write(struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st_vars = &ATTACHMENT(key)->client.request;
    if (selector_set_interest(key->s, sock->client_fd, OP_WRITE) != SELECTOR_SUCCESS) {
        logger_log(DEBUG, "failed selector\n");
        do_before_error(key);
        return ERROR;
    }
    if (request_marshall(st_vars->write_buf, st_vars->reply_code, 
            (sock->origin_domain == AF_INET) ? address_ipv4 : address_ipv6) < 0) {
        logger_log(DEBUG, "failed request_marshall\n");
        do_before_error(key);
        return ERROR;
    }
    return REQUEST_WRITE;
}

static enum connect_result 
try_connect(struct selector_key * key, struct addrinfo * node) {
    struct socks5 * sock = ATTACHMENT(key);
    if((sock->origin_fd = socket(node->ai_family, node->ai_socktype, node->ai_protocol)) < 0) {
        logger_log(DEBUG, "failed socket creation\n");
        goto errors;
    }
    /* Agrego referencia en el sock, se agrega un fd */
    sock->references += 1;
    if (selector_fd_set_nio(sock->origin_fd) < 0) {
        logger_log(DEBUG, "failed selector_set_nio\n");
        goto errors;
    }
    /* Connecting to origin_server */
    if (connect(sock->origin_fd, node->ai_addr, node->ai_addrlen) < 0) {
        if (errno == EINPROGRESS) {
            logger_log(DEBUG, "EINPROGRESS\n");
            /* Espero a poder escribirle al origin_server para determinar si me pude conectar */
            if (selector_register(key->s, sock->origin_fd, &socks5_handler, OP_WRITE, key->data, CON_TIMEOUT) != SELECTOR_SUCCESS) {
                logger_log(DEBUG, "failed selector\n");
                goto errors;
            }
            return CON_INPROG;
        } else {
            logger_log(DEBUG, "\n\nError. errno message: %s\n\n", strerror(errno));
            if (errno == ENETUNREACH) {
                sock->client.request.reply_code = REQUEST_RESPONSE_NET_UNREACH;
            } else {
                sock->client.request.reply_code = REQUEST_RESPONSE_HOST_UNREACH;
            }
            goto errors;
        }
    }
    /* Si me conecte, por ahora no necesito esperar nada de origin, voy a escribirle a client */
    if (selector_register(key->s, sock->origin_fd, &socks5_handler, OP_NOOP, key->data, GEN_TIMEOUT) != SELECTOR_SUCCESS) {
        logger_log(DEBUG, "failed selector\n");
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
    sock->origin_domain = node->ai_family;
    return CON_ERROR;
}

unsigned request_connect(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct addrinfo * node = sock->client.request.current;
    if (node == NULL) {
        return try_next_option(key);
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
            memcpy(&(sock->origin_addr), node->ai_addr, node->ai_addrlen);
            sock->origin_addr_len = node->ai_addrlen;
            sock->origin_domain = node->ai_family;
            sock->client.request.reply_code = REQUEST_RESPONSE_SUCCESS;
            return try_jump_request_write(key);
        case CON_ERROR:
            return try_next_option(key);
        default:
            /* Invalid result */
            abort();
    }
}

unsigned request_connect_write(struct selector_key *key) {
    logger_log(DEBUG, "Gonna get SOL_SOCKET option\n");
    struct socks5 * sock = ATTACHMENT(key);
    /* Reviso que haya sido por origin_fd, no deberia ser por otra cosa */
    if (key->fd != sock->origin_fd) {
        abort();
    }
    /* Si me conecte o no, por ahora no necesito esperar nada de origin, voy a escribirle a client */
    if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
        logger_log(DEBUG, "failed selector\n");
        do_before_error(key);
        return ERROR;
    }
    unsigned optval = 1, optlen = sizeof(optval);
    if (getsockopt(sock->origin_fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0
            || optval != 0) {
        /* Desregistro el fd y lo cierro */
        if (selector_unregister_fd(key->s, sock->origin_fd) != SELECTOR_SUCCESS) {
            logger_log(DEBUG, "failed selector\n");
            do_before_error(key);
            return ERROR;
        }
        close(sock->origin_fd);
        sock->origin_fd = -1;
        sock->client.request.reply_code = REQUEST_RESPONSE_HOST_UNREACH;
        /* Avanzo al siguiente nodo e intento conectarme */
        logger_log(DEBUG, "this one failed, go to next. Optval: %d\n", optval);
        sock->client.request.current = sock->client.request.current->ai_next;
        return request_connect(key);
    }
    /* Ya estableci la conexion, cambio la opcion de timeout */
    selector_set_timeout_option(key->s, sock->origin_fd, GEN_TIMEOUT);

    struct addrinfo * node = sock->client.request.current;
    memcpy(&(sock->origin_addr), node->ai_addr, node->ai_addrlen);
    sock->origin_addr_len = node->ai_addrlen;
    sock->origin_domain = node->ai_family;
    sock->client.request.reply_code = REQUEST_RESPONSE_SUCCESS;
    return try_jump_request_write(key);
}

void request_write_init(const unsigned state, struct selector_key *key) {
    /* Do nothing */
    access_log(ATTACHMENT(key));
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
    ssize_t n = send(key->fd, buf_read_ptr, nbytes, MSG_NOSIGNAL);

    if (n > 0) {
        buffer_read_adv(st_vars->write_buf, n);
        if (!buffer_can_read(st_vars->write_buf)) { // Termine de enviar el mensaje
            if (st_vars->reply_code == REQUEST_RESPONSE_SUCCESS) {
                if (selector_set_interest(key->s, sock->client_fd, OP_READ) == SELECTOR_SUCCESS && 
                        selector_set_interest(key->s, sock->origin_fd, OP_READ) == SELECTOR_SUCCESS) {
                    ret = COPY;
                } else {
                    logger_log(DEBUG, "failed selector\n");
                    ret = ERROR;
                }
            } else {
                logger_log(DEBUG, "%s\n", request_reply_code_description(sock->client.request.reply_code));
                ret = ERROR;
            }
        }
    } else {
        logger_log(DEBUG, "request write send failed\n");
        ret = ERROR;
    }

    return ret;
}

void request_close(const unsigned state, struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st = &sock->client.request;
    // if (st->parser.dest != NULL && st->parser.dest->address_type != address_fqdn && sock->origin_resolution != NULL) {
    //     free(sock->origin_resolution->ai_addr);
    // }
    logger_log(DEBUG, "saliendo de req write\n");
    request_parser_close(&st->parser);
    freeDohParser(&st->doh_parser);
    if (st->doh_fd != -1) {
        close(st->doh_fd);
    }
}

#define MAX_ADDRESS_LENGTH  45

static void access_log(struct socks5 * sock) {
    time_t t = time(NULL);
    if (t == ((time_t) -1))
        return;
    struct tm * tm_st = localtime(&t);
    if (tm_st == NULL)
        return;

    struct destination * dest = sock->client.request.parser.dest;
    char * ip_server;
    uint16_t port;
    struct sockaddr * addr_ptr;
    if (dest != NULL && dest->address != NULL) {
        struct sockaddr_in address;
        struct sockaddr_in6 address6;
        switch (dest->address_type)
        {
            case address_ipv4:
                address = get_origin_addr_ipv4(dest);
                addr_ptr = (struct sockaddr *) &address;
                break;
            case address_ipv6:
                address6 = get_origin_addr_ipv6(dest);
                addr_ptr = (struct sockaddr *) &address6;
                break;
            case address_fqdn:
                break;
            default:
                return;
        }
        if (dest->address_type != address_fqdn) {
            ip_server = calloc(MAX_ADDRESS_LENGTH + 1, sizeof(char));
            if (ip_server == NULL) return;
            sockaddr_to_human_no_port(ip_server, MAX_ADDRESS_LENGTH, addr_ptr);
            port = dest->port;
        } else {
            ip_server = (char *) dest->address;
            port = dest->port;
        }
    } else {
        ip_server = "????";
        port = 0;
    }

    const struct sockaddr * clientaddr = (struct sockaddr *) &sock->client_addr;
    char * ip_client = calloc(MAX_ADDRESS_LENGTH + 1, sizeof(char));
    if(ip_client == NULL) return;
    sockaddr_to_human_no_port(ip_client, MAX_ADDRESS_LENGTH, clientaddr);
    uint16_t port_client = get_port_from_sockaddr((struct sockaddr *) &sock->client_addr);

    logger_log(ACCESS_LOG, "\n%d-%02d-%02dT%02d:%02d:%02dZ\t%s\t%c\t%s\t%d\t%s\t%d\t%d\n\n", 
        tm_st->tm_year + 1900, tm_st->tm_mon + 1, tm_st->tm_mday, tm_st->tm_hour, tm_st->tm_min, tm_st->tm_sec, 
            sock->username, ACCESS_CHAR,  ip_client, port_client, ip_server, port, sock->client.request.reply_code);

    if (dest != NULL && dest->address != NULL && dest->address_type != address_fqdn){
        free(ip_server);
    }
    free(ip_client);
}