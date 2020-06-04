#include <stdlib.h> // malloc
#include <string.h> // memset

#include <sys/socket.h>
#include <netdb.h>

#include "socks5.h"
#include "selector.h"
#include "buffer.h"
#include "stm.h"
#include "socks5mt.h"

#include "hello.h"
#include "negotiation.h"
#include "request.h"

#include "sm_hello_state.h"

// Retorna la cantidad de elementos de un arreglo
#define N(x) (sizeof(x)/sizeof(x[0]))

/* Definicion de variables para cada estado */


// NEGOT_READ y NEGOT_WRITE
typedef struct negot_st {
    buffer * read_buf, write_buf;
    struct negot_parser parser;
} negot_st;

// REQUEST_READ, REQUEST_RESOLV, REQUEST_CONNECT y REQUEST_WRITE
typedef struct request_st {
    buffer * read_buf, write_buf;
    struct request_parser parser;
} request_st;

// COPY
typedef struct copy_st {
    buffer * read_buf, write_buf;
} copy_st;

// CONNECTING (origin_server)
typedef struct connecting_st {
    buffer * read_buf, write_buf;
} connecting_st;

struct socks5 {
    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct hello_st     hello;
        struct negot_st     negot;
        struct request_st   request;
        struct copy_st      copy;
    } client;
    /** estados para el origin_fd */
    union {
        struct connecting_st   conn;
        struct copy_st         copy;
    } origin;
    
    /* Informacion del cliente */
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_fd;

    /* Resolucion de la direc del origin server */
    struct addrinfo * origin_resolution;
    int origin_fd;
};

/* Destruye realmente el struct socks5 */
static void
socks5_destroy_(struct socks5 * s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct socks5 *s) {
    /* if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        if(s != NULL) {
            if(pool_size < max_pool) {
                s->next = pool;
                pool    = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    } */
}

/* Libera la lista entera de socks5 */
void
socks5_pool_destroy(void) {
    /* struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    } */
}

/** obtiene el struct (socks5 *) desde la llave de seleccion  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

static void socks5_read(selector_key * key);
static void socks5_write(selector_key * key);
static void socks5_block(selector_key * key);
static void socks5_close(selector_key * key);

static const fd_handler socks5_handler = {
    .handle_read = socks5_read,
    .handle_write = socks5_write,
    .handle_block = socks5_block,
    .handle_close = socks5_close,
};

/* Crea un nuevo struct socks5 */
static struct socks5 * socks5_new(int client_fd) {
    return NULL;
}

/* Intenta aceptar la nueva conexion entrante */
void
socks5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len   = sizeof(client_addr);
    struct socks5 * state       = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr,
                                                          &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = socks5_new(client);
    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se libero alguna conexion.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

// Handlers top level de la conexiÃ³n pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
socks5_done(struct selector_key* key);

static void
socks5_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks5_state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        socks5_done(key);
    }
}

static void
socks5_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks5_state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        socks5_done(key);
    }
}

static void
socks5_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks5_state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socks5_done(key);
    }
}

static void
socks5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void
socks5_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}