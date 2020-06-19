#include <errno.h>
#include <arpa/inet.h>

#include "socks5mt.h"
#include "logger.h"
#include "socks5_handler.h"
#include "sm_before_error_state.h"
#include "dohParser.h"

static struct doh doh_info;

static unsigned prepare_blocking_doh(struct selector_key * key);
static unsigned build_doh_query(struct selector_key * key);

void set_doh_info(struct doh info) {
    doh_info = info;
}

static enum connect_result 
try_connect_doh(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct connect_st * st = &sock->client.connect;

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
    if (selector_fd_set_nio(st->doh_fd) < 0) {
        logger_log(DEBUG, "failed selector_set_nio\n");
        goto errors;
    }
    /* Connecting to doh server */
    if (connect(st->doh_fd, addr_ptr, addr_len) < 0) {
        if (errno == EINPROGRESS) {
            logger_log(DEBUG, "EINPROGRESS\n");
            /* Espero a poder escribirle al doh server para determinar si me pude conectar */
            if (selector_register(key->s, st->doh_fd, &socks5_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
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
    if (selector_register(key->s, st->doh_fd, &socks5_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
        logger_log(DEBUG, "failed selector\n");
        goto errors;
    }
    return CON_OK;
errors:
    if (st->doh_fd >= 0) {
        close(st->doh_fd);
        st->doh_fd = -1;
    }
    return CON_ERROR;
}

static void init_connect_st(struct selector_key * key) {
    struct connect_st * st = &ATTACHMENT(key)->client.connect;
    st->doh_fd = -1;
    st->option = doh_ipv4;
    st->read_buf = &(ATTACHMENT(key)->read_buffer);
    st->write_buf = &(ATTACHMENT(key)->write_buffer);
}

unsigned start_doh_connect(struct selector_key * key) {
    init_connect_st(key);
    return connect_doh_server(key);
}

unsigned connect_doh_server(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    // init_connect_st(key); // Ver donde va esto

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
        break;
    }
}

static unsigned build_doh_query(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct connect_st * st = &sock->client.connect;

    if (doh_query_marshall(st->write_buf, sock->fqdn, doh_info, st->option) < 0) {
        return prepare_blocking_doh(key);
    }
    return DNS_WRITE;
}

unsigned dns_connect_write(struct selector_key * key) {
    logger_log(DEBUG, "Gonna get SOL_SOCKET option\n");
    struct socks5 * sock = ATTACHMENT(key);
    struct connect_st * st = &sock->client.connect;
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
        /* Defaulteo a getaddrinfo */
        return prepare_blocking_doh(key);
    }
    /* Me mantengo interesado en escribir en doh_fd */
    return build_doh_query(key);
}

unsigned dns_write(struct selector_key *key) {
    struct connect_st * st_vars = &ATTACHMENT(key)->client.connect;
    unsigned ret = DNS_WRITE;
    size_t nbytes;
    uint8_t * buf_read_ptr = buffer_read_ptr(st_vars->write_buf, &nbytes);
    ssize_t n = send(key->fd, buf_read_ptr, nbytes, MSG_NOSIGNAL);

    if (n > 0) {
        buffer_read_adv(st_vars->write_buf, n);
        if (!buffer_can_read(st_vars->write_buf)) { // Termine de enviar el mensaje
            if (selector_set_interest_key(key, OP_READ) == SELECTOR_SUCCESS) {
                ret = DNS_READ; 
            } else {
                do_before_error(key);
                ret = ERROR;
            }
        }
    } else {
        do_before_error(key);
        ret = ERROR;
    }

    return ret;
}

void dns_read_init(const unsigned state, struct selector_key *key) {
    struct connect_st * st = &ATTACHMENT(key)->client.connect;
    doh_parser_init(&st->parser);
}

unsigned dns_read(struct selector_key *key) {
    struct connect_st * st_vars = &ATTACHMENT(key)->client.connect;
    unsigned ret = DNS_READ;
    bool errored = false;
    size_t nbytes;
    uint8_t * buf_write_ptr = buffer_write_ptr(st_vars->read_buf, &nbytes);
    ssize_t n = recv(key->fd, buf_write_ptr, nbytes, 0);

    if (n > 0) {
        buffer_write_adv(st_vars->read_buf, n);
        const DOHQRSM_STATE st = doh_parser_consume(st_vars->read_buf, &st_vars->parser, &errored);
        if (doh_parser_is_done(st, 0)) {
            ret = dns_answer_process(st_vars, errored);
        }
    } else {
        ret = ERROR;
    }

    return ret;
}

unsigned dns_answer_process(struct selector_key *key, bool errored) {
    struct connect_st * st_vars = &ATTACHMENT(key)->client.connect;
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
        if (st_vars->option == doh_ipv4) {
            freeDohParser(&st_vars->parser);
            st_vars->option = doh_ipv6;
            return connect_doh_server(key);
        } else {
            /* Defaulteo a getaddrinfo */
            return prepare_blocking_doh(key);
        }
    } else {
        /* Si fue exitoso, intento conectarme */
        return request_connect(key);
    }
}

unsigned try_next_option(struct selector_key * key) {
    struct socks5 * sock = ATTACHMENT(key);
    struct connect_st * st_vars = &sock->client.connect;
    
    /* Check if there is another option to try. */
    if (sock->fqdn == NULL || st_vars->option == default_function) {
        /* Could not connect to any ip address */
        logger_log(DEBUG, "could not connect to any ip address\n");
        if (sock->client.request.reply_code == REQUEST_RESPONSE_SUCCESS) {
            sock->client.request.reply_code = REQUEST_RESPONSE_GEN_SOCK_FAIL;
        }
        return try_jump_request_write(key);
    }
    
    if (st_vars->option == doh_ipv4) {
        freeDohParser(&st_vars->parser);
        st_vars->option = doh_ipv6;
        return connect_doh_server(key);
    } else if (st_vars->option == doh_ipv6) {
        /* Defaulteo a getaddrinfo */
        return prepare_blocking_doh(key);
    }
}

static unsigned prepare_blocking_doh(struct selector_key * key) {
    struct connect_st * st_vars = &ATTACHMENT(key)->client.connect;
    st_vars->option = default_function;


    return DNS_SOLVE_BLK;
}

/** TODO: REVISAR DE CERRAR SIEMPRE EL FD  */