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

// Retorna la cantidad de elementos de un arreglo
#define N(x) (sizeof(x)/sizeof(x[0]))

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
/* static void
socks5_destroy(struct socks5 *s) {
    if(s == NULL) {
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
    }
} */

/* Libera el pool entero de socks5 */
/* void
socks5_pool_destroy(void) {
    struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
} */

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
    struct socks5 * ret = calloc(1, sizeof(*ret));
    if (ret == NULL) {
        return ret;
    }
    ret->origin_fd = -1;
    ret->client_fd = client_fd;
    // ret->client_addr_len = sizeof(ret->client_addr);

    ret->stm.initial = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states = client_statbl;
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer, N(ret->read_buffer_mem), ret->read_buffer_mem);
    buffer_init(&ret->write_buffer, N(ret->write_buffer_mem), ret->write_buffer_mem);

    return ret;
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
    socks5_destroy_(state);
}

// Handlers top level de la conexion pasiva.
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
    socks5_destroy_(ATTACHMENT(key));
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