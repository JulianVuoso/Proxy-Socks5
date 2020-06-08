#ifndef HANDLERS_H_d4f12e31ae9fe3878d44027fdab552d63b292952
#define HANDLERS_H_d4f12e31ae9fe3878d44027fdab552d63b292952

#include <sys/socket.h>
#include "stm.h"
#include "selector.h"
#include "buffer.h"

#include "sm_hello_state.h"
#include "sm_request_state.h"
#include "sm_copy_state.h"

// Borrar cuando tenga su sm_state
#include "negotiation.h"

/* Maquina de estados general */
enum socks5_state {
    /*
     * recibe el mensaje `hello` del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - HELLO_READ  mientras el mensaje no esta completo
     *   - HELLO_WRITE cuando esta completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */
    HELLO_READ,

    /**
     * envi­a la respuesta del `hello' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    HELLO_WRITE,

    /**
     * recibe el mensaje de autenticacion del cliente.
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - NEGOT_READ   mientras el mensaje no esta completo
     *   - NEGOT_WRITE  cuando esta completo
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    NEGOT_READ,

    /**
     * envi­a la respuesta de la autenticacion al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - NEGOT_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo/credenciales)
     */
    NEGOT_WRITE,

    /**
     * recibe un request del cliente y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_READ     mientras el request no esta completo
     *   - REQUEST_SOLVE    si esta completo y es un fqdn
     *   - REQUEST_CONNECT  si esta completo, NO es un fqdn y se puede 
     *                      establecer la conexion al origin server
     *   - REQUEST_WRITE    si hay un error de soporte de comando o similar
     *   - ERROR            ante cualquier error (IO/parseo)
     */
    REQUEST_READ,

    /**
     * resuelve un fqdn a una lista de direcciones IP (v4 o v6).
     *
     * Intereses:
     *     - OP_NOOP sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_CONNECT  si resuelve correctamente el fqdn y se puede
     *                      establecer la conexion al origin server
     *   - REQUEST_WRITE    si no puede resolver el fqdn, responde != 00
     */
    REQUEST_SOLVE,

    /**
     * Se espera a que la conexion este establecida // TODO: PUEDE NO ESTABLECERSE?
     *
     * Intereses:
     *     - OP_WRITE sobre origin_fd
     * 
     * Transiciones:
     *   - REQUEST_WRITE    en caso satisfactorio o de error
     */
    REQUEST_CONNECT,

    /**
     * escribe la respuesta del request al cliente
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *     - OP_NOOP  sobre origin_fd
     *
     * Transiciones:
     *   - REQUEST_WRITE    mientras queden bytes por enviar
     *   - COPY             si no quedan bytes y el request fue exitoso
     *   - ERROR            por error de I/O
     */
    REQUEST_WRITE,

    /**
     * copia la respuesta del origin server en el cliente
     *
     * Intereses: (inicialmente solo OP_READ en client_fd)
     *     - OP_READ  sobre client_fd y origin_fd si tienen espacio para 
     *                escribir en su buffer de lectura
     *     - OP_WRITE sobre client_fd y origin_fd si tienen bytes para 
     *                leer en su buffer de escritura
     *
     * Transiciones:
     *   - COPY         mientras queden bytes por copiar
     *   - DONE         si terminamos de copiar
     *   - ERROR        por error de I/O
     */
    COPY,

    /* Estado terminal */
    DONE,

    /* Estado terminal */
    ERROR,
};

void error_arrival(const unsigned state, struct selector_key *key);

static const struct state_definition client_statbl[] = {
    {
        .state            = HELLO_READ,
        .on_arrival       = hello_read_init,
        .on_departure     = hello_read_close,
        .on_read_ready    = hello_read,
    },
    {
        .state            = HELLO_WRITE,
        .on_arrival       = hello_write_init,
        .on_departure     = hello_write_close,
        .on_write_ready   = hello_write,
    },
    {
        .state            = NEGOT_READ,
        .on_arrival       = error_arrival,
    },
    {
        .state            = NEGOT_WRITE,
        .on_arrival       = error_arrival,
    },
    {
        .state            = REQUEST_READ,
        .on_arrival       = request_read_init,
        .on_departure     = request_read_close,
        .on_read_ready    = request_read,
    },
    {
        .state            = REQUEST_SOLVE,
        .on_arrival       = error_arrival,
    },
    {
        .state            = REQUEST_CONNECT,
        .on_write_ready   = request_connect_write,
    },
    {
        .state            = REQUEST_WRITE,
        .on_arrival       = request_write_init,
        .on_departure     = request_write_close,
        .on_write_ready   = request_write,
    },
    {
        .state            = COPY,
        .on_arrival       = copy_init,
        .on_read_ready    = copy_read,
        .on_write_ready   = copy_write,
    },
    {
        .state            = DONE,
    },
    {
        .state            = ERROR,
    },
};

/** obtiene el struct (socks5 *) desde la llave de seleccion  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

#define INITIAL_BUF_SIZE 2048

/* Definicion de variables para cada estado */

// NEGOT_READ y NEGOT_WRITE
typedef struct negot_st {
    buffer * read_buf, * write_buf;
    struct negot_parser parser;
} negot_st;

struct socks5 {
    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el cliente */
    union {
        struct hello_st     hello;
        struct negot_st     negot;
        struct request_st   request;
        struct copy_st      copy;
    } client;

    /* Informacion del cliente */
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_fd;

    /* Resolucion de la direc del origin server */
    struct sockaddr_storage origin_addr;
    socklen_t origin_addr_len;
    int origin_fd, origin_domain;
    struct addrinfo * origin_resolution;

    /* Buffers */
    uint8_t read_buffer_mem[INITIAL_BUF_SIZE], write_buffer_mem[INITIAL_BUF_SIZE];
    buffer read_buffer, write_buffer;

    /* Reference count. If 1, it is destroyed */
    unsigned references;
    /* Proxy Server fd to update interest if needed when destroyed */
    int proxy_fd;
};

#endif