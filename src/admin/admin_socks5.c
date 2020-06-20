#include <stdlib.h> // malloc
#include <string.h> // memset

#include <sys/socket.h>
#include <netdb.h>

#include "admin_socks5.h"
#include "buffer.h"
#include "stm.h"
#include "adminmt.h"
#include "admin_handler.h"

#include "logger.h"

// Retorna la cantidad de elementos de un arreglo
#define N(x) (sizeof(x)/sizeof(x[0]))

/** obtiene el struct (admin *) desde la llave de seleccion  */
#define ADMIN_ATTACH(key) ( (struct admin *)(key)->data)

static unsigned admin_concurrent_connections = 0;

/* Destruye realmente el struct admin */
static void
admin_destroy_(struct selector_key *key) {
    struct admin * s = ADMIN_ATTACH(key);

    // Actualizar cantidad de conexiones concurrentes.
    // Habilitar OP_READ si estabamos en el maximo.
    if (admin_concurrent_connections == MAX_CONCURRENT_CON_ADMIN) {
        // Habilito OP_READ del socket pasivo (server solo usa OP_READ)
        selector_set_interest(key->s, s->proxy_fd, OP_READ);
    }
    admin_concurrent_connections--;
    
    free(s);
}

static void
admin_destroy(struct selector_key *key) {
    struct admin * s = ADMIN_ATTACH(key);
    if(s == NULL) {
        return;
    } 
    admin_destroy_(key);
}

/* Crea un nuevo struct admin */
static struct admin * admin_new(int client_fd) {
    struct admin * ret = calloc(1, sizeof(*ret));
    if (ret == NULL) {
        return ret;
    }
    ret->client_fd = client_fd;

    ret->stm.initial = ADMIN_NEGOT_READ;
    ret->stm.max_state = ADMIN_ERROR;
    ret->stm.states = admin_statbl;
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer, N(ret->read_buffer_mem), ret->read_buffer_mem);
    buffer_init(&ret->write_buffer, N(ret->write_buffer_mem), ret->write_buffer_mem);

    return ret;
}

/* Intenta aceptar la nueva conexion entrante de ADMIN */
void
admin_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len   = sizeof(client_addr);
    struct admin * state       = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr,
                                                          &client_addr_len);

    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = admin_new(client);
    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se libero alguna conexion.
        goto fail;
    }
    state->proxy_fd = key->fd;
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    // Actualizar cantidad de conexiones concurrentes.
    // Deshabilitar OP_READ si alcanzamos el maximo.
    admin_concurrent_connections++;
    if (admin_concurrent_connections == MAX_CONCURRENT_CON_ADMIN) {
        // Deshabilito OP_READ del socket pasivo (server solo usa OP_READ)
        selector_set_interest_key(key, OP_NOOP);
    }

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &admin_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    struct selector_key aux_key = {
        .s = key->s,
        .fd = -1,
        .data = state,
    };
    admin_destroy(&aux_key);
}

// Handlers top level de la conexion pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
admin_done(struct selector_key* key);

void admin_read(struct selector_key *key) {
    struct state_machine *stm   = &ADMIN_ATTACH(key)->stm;
    const enum admin_state st = stm_handler_read(stm, key);

    if(ADMIN_ERROR == st || ADMIN_DONE == st) {
        admin_done(key);
    }
}

void admin_write(struct selector_key *key) {
    struct state_machine *stm   = &ADMIN_ATTACH(key)->stm;
    const enum admin_state st = stm_handler_write(stm, key);

    if(ADMIN_ERROR == st || ADMIN_DONE == st) {
        admin_done(key);
    }
}

void admin_block(struct selector_key *key) {
    struct state_machine *stm   = &ADMIN_ATTACH(key)->stm;
    const enum admin_state st = stm_handler_block(stm, key);

    if(ADMIN_ERROR == st || ADMIN_DONE == st) {
        admin_done(key);
    }
}

void admin_close(struct selector_key *key) {
    admin_destroy(key);
}

static void
admin_done(struct selector_key* key) {
    int fd = ADMIN_ATTACH(key)->client_fd;
    if (fd != -1) {
        if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fd)) {
            abort();
        }
        close(fd);
    }
}