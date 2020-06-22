#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>      // getaddrinfo
#include <pthread.h>
#include <netinet/in.h>

#include "socks5mt.h"
#include "logger.h"
#include "socks5_handler.h"
#include "sm_actions.h"
#include "dohParser.h"

static struct doh doh_info;

static unsigned build_doh_query(struct selector_key * key);

void set_doh_info(struct doh info) {
    doh_info = info;
}

static enum connect_result 
try_connect_doh(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st = &sock->client.request;

    struct sockaddr * addr_ptr;
    struct sockaddr_in address;
    struct sockaddr_in6 address6;
    socklen_t addr_len;
    switch (doh_info.ip_family)
    {
        case AF_INET:
            if (inet_pton(AF_INET, doh_info.ip, &address.sin_addr) <= 0) {
                logger_log(DEBUG, "failed inet pton in doh\n");
                goto errors;
            }
            address.sin_family = AF_INET;
            address.sin_port = htons(doh_info.port);
            addr_len = sizeof(address);
            addr_ptr = (struct sockaddr *) &address;
            break;
        case AF_INET6:
            if (inet_pton(AF_INET6, doh_info.ip, &address6.sin6_addr) <= 0) {
                logger_log(DEBUG, "failed inet pton in doh\n");
                goto errors;
            }
            address6.sin6_family = AF_INET6;
            address6.sin6_port = htons(doh_info.port);
            addr_len = sizeof(address6);
            addr_ptr = (struct sockaddr *) &address6;
            break;
        default:
            /* Invalid address family */
            abort();
            break;
    }

    if((st->doh_fd = socket(doh_info.ip_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        logger_log(DEBUG, "failed socket creation\n");
        goto errors;
    }
    /* Agrego referencia en el sock, se agrega un fd */
    sock->references += 1;
    if (selector_fd_set_nio(st->doh_fd) < 0) {
        logger_log(DEBUG, "failed selector_set_nio\n");
        goto errors;
    }
    logger_log(DEBUG, "DNS ip: %s\n", doh_info.ip);
    /* Connecting to doh server */
    if (connect(st->doh_fd, addr_ptr, addr_len) < 0) {
        if (errno == EINPROGRESS) {
            logger_log(DEBUG, "EINPROGRESS\n");
            /* Espero a poder escribirle al doh server para determinar si me pude conectar */
            if (selector_register(key->s, st->doh_fd, &socks5_handler, OP_WRITE, key->data, CON_TIMEOUT) != SELECTOR_SUCCESS) {
                logger_log(DEBUG, "failed selector\n");
                goto errors;
            }
            return CON_INPROG;
        } else {
            logger_log(DEBUG, "\n\nError. errno message: %s\n\n", strerror(errno));
            goto errors;
        }
    }
    /* Si me conecte, voy a escribirle al server para enviarle la consulta DNS */
    if (selector_register(key->s, st->doh_fd, &socks5_handler, OP_WRITE, key->data, GEN_TIMEOUT) != SELECTOR_SUCCESS) {
        logger_log(DEBUG, "failed selector\n");
        goto errors;
    }
    return CON_OK;
errors:
    if (st->doh_fd >= 0) {
        close(st->doh_fd);
        st->doh_fd = -1;
        sock->references -= 1;
    }
    return CON_ERROR;
}

static void init_connect_st(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st = &sock->client.request;
    st->doh_fd = -1;
    sock->option = doh_ipv4;
}

unsigned start_doh_connect(struct selector_key * key) {
    init_connect_st(key);
    return connect_doh_server(key);
}

unsigned connect_doh_server(struct selector_key * key) {
    enum connect_result res = try_connect_doh(key);
    switch (res)
    {
        case CON_INPROG:
            return DNS_CONNECT;
        case CON_OK:
            return build_doh_query(key);
        case CON_ERROR:
            /* Default to getaddrinfo */
            return prepare_blocking_doh(key);
        default:
            /* Invalid connect_result */
            abort();
            break;
    }
}

static unsigned build_doh_query(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st = &sock->client.request;

    if (doh_query_marshall(st->write_buf, sock->fqdn, doh_info, sock->option) < 0) {
        return prepare_blocking_doh(key);
    }
    logger_log(DEBUG, "going to dns write\n");
    return DNS_WRITE;
}

unsigned dns_connect_write(struct selector_key * key) {
    logger_log(DEBUG, "Gonna get SOL_SOCKET option\n");
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st = &sock->client.request;
    /* Reviso que haya sido por doh_fd, no deberia ser por otra cosa */
    if (key->fd != st->doh_fd) {
        abort();
    }
    unsigned optval = 1, optlen = sizeof(optval);
    if (getsockopt(st->doh_fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0
            || optval != 0) {
        /* Desregistro el fd y lo cierro */
        if (selector_unregister_fd(key->s, st->doh_fd) != SELECTOR_SUCCESS) {
            logger_log(DEBUG, "failed selector\n");
            do_before_error(key);
            return ERROR;
        }
        close(st->doh_fd);
        st->doh_fd = -1;
        logger_log(DEBUG, "DOH server connect failed\n");
        /* Defaulteo a getaddrinfo */
        return prepare_blocking_doh(key);
    }
    /* Ya estableci la conexion, cambio la opcion de timeout */
    selector_set_timeout_option(key->s, st->doh_fd, GEN_TIMEOUT);
    /* Me mantengo interesado en escribir en doh_fd */
    return build_doh_query(key);
}

unsigned dns_write(struct selector_key *key) {
    struct request_st * st_vars = &ATTACHMENT(key)->client.request;
    unsigned ret = DNS_WRITE;
    size_t nbytes;
    uint8_t * buf_read_ptr = buffer_read_ptr(st_vars->write_buf, &nbytes);
    ssize_t n = send(key->fd, buf_read_ptr, nbytes, MSG_NOSIGNAL);

    if (n > 0) {
        buffer_read_adv(st_vars->write_buf, n);
        if (!buffer_can_read(st_vars->write_buf)) { // Termine de enviar el mensaje
            if (selector_set_interest_key(key, OP_READ) == SELECTOR_SUCCESS) {
                ret = DNS_READ;
                logger_log(DEBUG, "going to dns read\n");
            } else {
                do_before_error(key);
                ret = ERROR;
            }
        }
    } else {
        logger_log(DEBUG, "DOH server write failed\n");
        /* Defaulteo a getaddrinfo */
        return prepare_blocking_doh(key);
    }

    return ret;
}

void dns_read_init(const unsigned state, struct selector_key *key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st = &sock->client.request;
    doh_parser_init(&st->doh_parser, sock->option);
}

unsigned dns_read(struct selector_key *key) {
    struct request_st * st_vars = &ATTACHMENT(key)->client.request;
    unsigned ret = DNS_READ;
    bool errored = false;
    size_t nbytes;
    uint8_t * buf_write_ptr = buffer_write_ptr(st_vars->read_buf, &nbytes);
    ssize_t n = recv(key->fd, buf_write_ptr, nbytes, 0);

    if (n > 0) {
        buffer_write_adv(st_vars->read_buf, n);
        const DOHQRSM_STATE st = doh_parser_consume(st_vars->read_buf, &st_vars->doh_parser, &errored);
        if (doh_parser_is_done(st, 0)) {
            ret = dns_answer_process(key, errored);
        }
    } else {
        logger_log(DEBUG, "DOH server read failed\n");
        /* Defaulteo a getaddrinfo */
        return prepare_blocking_doh(key);
    }

    return ret;
}

static struct addrinfo *
set_current_addrinfo(struct addrinfo * current, struct sockaddr * sock_address, int family, uint8_t length) {
    struct addrinfo * ret = calloc(1, sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }
    ret->ai_family = family;
    ret->ai_addr = malloc(length);
    if (ret->ai_addr == NULL) {
        return NULL;
    }
    memcpy(ret->ai_addr, sock_address, length);
    ret->ai_addrlen = length;
    ret->ai_next = current;
    ret->ai_socktype = SOCK_STREAM;
    ret->ai_protocol = IPPROTO_TCP;
    return ret;
}

static int set_origin_resolution_ipv4(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * con_st = &sock->client.request;
    struct destination * dest = con_st->parser.dest;

    logger_log(DEBUG, "setting origin_resolution ipv4\n");
    static struct addrinfo * aux;
    struct sockaddr_in address;
    for (uint8_t i = 0; i < con_st->doh_parser.rCount; i++) {
        DNSResRec rec = con_st->doh_parser.records[i];
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        memcpy(&address.sin_addr, rec.rddata, rec.rdlength);
        address.sin_port = htons(dest->port);
        aux = set_current_addrinfo(sock->origin_resolution, (struct sockaddr *) &address, AF_INET, sizeof(address));
        if (aux == NULL) {
            /* Free list */
            return -1;
        }
        sock->origin_resolution = aux;
    }
    sock->client.request.current = sock->origin_resolution;
    return 0;
}

static int set_origin_resolution_ipv6(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * con_st = &sock->client.request;
    struct destination * dest = con_st->parser.dest;

    logger_log(DEBUG, "setting origin_resolution ipv4\n");
    static struct addrinfo * aux;
    struct sockaddr_in6 address;
    for (uint8_t i = 0; i < con_st->doh_parser.rCount; i++) {
        DNSResRec rec = con_st->doh_parser.records[i];
        memset(&address, 0, sizeof(address));
        address.sin6_family = AF_INET6;
        memcpy(&address.sin6_addr, rec.rddata, rec.rdlength);
        address.sin6_port = htons(dest->port);
        aux = set_current_addrinfo(sock->origin_resolution, (struct sockaddr *) &address, AF_INET6, sizeof(address));
        if (aux == NULL) {
            /* Free list */
            return -1;
        }
        sock->origin_resolution = aux;
    }
    sock->client.request.current = sock->origin_resolution;
    return 0;
}

unsigned dns_answer_process(struct selector_key *key, bool errored) {
    logger_log(DEBUG, "processing dns answer\n");
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st_vars = &sock->client.request;
    /* Desregistro el fd y lo cierro */
    if (selector_unregister_fd(key->s, st_vars->doh_fd) != SELECTOR_SUCCESS) {
        logger_log(DEBUG, "failed selector\n");
        do_before_error(key);
        return ERROR;
    }
    close(st_vars->doh_fd);
    st_vars->doh_fd = -1;
    
    /* Si fue con error */
    if (errored) {
        /* Si estaba en IPv4, intento nuevamente con IPv6 */
        if (sock->option == doh_ipv4) {
            freeDohParser(&st_vars->doh_parser);
            sock->option = doh_ipv6;
            return connect_doh_server(key);
        } else {
            /* Defaulteo a getaddrinfo */
            return prepare_blocking_doh(key);
        }
    } else {
        /* Si fue exitoso, seteo origin_resolution */
        if (sock->option == doh_ipv4) {
            if (set_origin_resolution_ipv4(key) < 0) {
                logger_log(DEBUG, "failed set_origin_resolution_ipv4\n");
                do_before_error(key);
                return ERROR;
            }
        } else {
            if (set_origin_resolution_ipv6(key) < 0) {
                logger_log(DEBUG, "failed set_origin_resolution_ipv6\n");
                do_before_error(key);
                return ERROR;
            }
        }
        logger_log(DEBUG, "trying to connect\n");
        /* Intento conectarme */
        return request_connect(key);
    }
}

unsigned try_next_option(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st_vars = &sock->client.request;
    
    /* Check if there is another option to try. */
    if (sock->fqdn == NULL || sock->option == default_function) {
        /* Could not connect to any ip address */
        logger_log(DEBUG, "could not connect to any ip address\n");
        if (sock->client.request.reply_code == REQUEST_RESPONSE_SUCCESS) {
            sock->client.request.reply_code = REQUEST_RESPONSE_GEN_SOCK_FAIL;
        }
        return try_jump_request_write(key);
    }
    
    if (sock->option == doh_ipv4) {
        freeDohParser(&st_vars->doh_parser);
        sock->option = doh_ipv6;
        return connect_doh_server(key);
    } else {
        /* Defaulteo a getaddrinfo */
        return prepare_blocking_doh(key);
    }
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
    logger_log(DEBUG, "Resolviendo DNS con getaddrinfo...\n");
    if (getaddrinfo((char *) dest->address, port, &hints, &sock->origin_resolution) != 0) {
        /* If getaddrinfo fails, freeaddrinfo and set res to NULL */
        freeaddrinfo(sock->origin_resolution);
        sock->origin_resolution = NULL;
        logger_log(DEBUG, "getaddrinfo failed. Error msg: %s\n", gai_strerror(errno));
    }
    logger_log(DEBUG, "Finalizo la resolucion DNS con getaddrinfo...\n");

    /* Aviso que termino al CLIENT FD, el de la key capaz lo cerre ya */
    selector_notify_block(key->s, sock->client_fd);

    free(args);
    return 0;
}

unsigned prepare_blocking_doh(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    sock->option = default_function;

    struct request_st * req_st_vars = &sock->client.request;
    pthread_t thread_pid = 0;
    struct selector_key * key_param = malloc(sizeof(*key));
    if (key_param == NULL) {
        goto error;
    }
    memcpy(key_param, key, sizeof(*key_param));
    if (pthread_create(&thread_pid, 0, request_solve_blocking, key_param) != 0) {
        logger_log(DEBUG, "failed thread creation\n");
        goto error;
    }
    return DNS_SOLVE_BLK;

error:
    if (thread_pid != 0) {
        pthread_cancel(thread_pid);
    }
    req_st_vars->reply_code = REQUEST_RESPONSE_GEN_SOCK_FAIL;
    logger_log(DEBUG, "Error in request processing.\n");
    sock->origin_domain = (req_st_vars->parser.dest != NULL && req_st_vars->parser.dest->address_type == address_ipv6) ? AF_INET6 : AF_INET;
    return try_jump_request_write(key);
}

unsigned request_solve_block(struct selector_key *key) {
    logger_log(DEBUG, "solve unblock\n");
    struct socks5 * sock = ATTACHMENT(key);
    struct request_st * st_vars = &sock->client.request;
    if (sock->origin_resolution == NULL) {
        logger_log(DEBUG, "failed getaddrinfo\n");
        st_vars->reply_code = REQUEST_RESPONSE_HOST_UNREACH;
        sock->origin_domain = AF_INET;
        return try_jump_request_write(key);
    }
    sock->client.request.current = sock->origin_resolution;
    return request_connect(key);
}