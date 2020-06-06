#ifndef HANDLERS_H_d4f12e31ae9fe3878d44027fdab552d63b292952
#define HANDLERS_H_d4f12e31ae9fe3878d44027fdab552d63b292952

#include <sys/socket.h>
#include "stm.h"
#include "selector.h"
#include "buffer.h"

#include "sm_hello_state.h"

// Borrar cuando tenga su sm_state
#include "negotiation.h"
#include "request.h"

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
     * recibe un request del cliente.
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_READ     mientras el request no esta completo
     *   - REQUEST_RESOLV   si esta completo y es un fqdn
     *   - REQUEST_CONNECT  si esta completo y NO es un fqdn
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
     *   - REQUEST_CONNECT  si resuelve correctamente el fqdn
     *   - REQUEST_WRITE    si no puede resolver el fqdn, responde != 00
     */
    REQUEST_RESOLV,

    /**
     * realiza la conexion a la direccion y puerto
     *
     * Intereses:
     *     - ??
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
     *     - ??
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
     * Intereses:
     *     - OP_READ sobre origin_fd
     *     - OP_WRITE sobre client_fd
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
        .on_arrival       = error_arrival,
    },
    {
        .state            = REQUEST_RESOLV,
        .on_arrival       = error_arrival,
    },
    {
        .state            = REQUEST_CONNECT,
        .on_arrival       = error_arrival,
    },
    {
        .state            = REQUEST_WRITE,
        .on_arrival       = error_arrival,
    },
    {
        .state            = COPY,
        .on_arrival       = error_arrival,
    },
    {
        .state            = DONE,
        .on_arrival       = error_arrival,
    },
    {
        .state            = ERROR,
        .on_arrival       = error_arrival,
    },
};

/** obtiene el struct (socks5 *) desde la llave de seleccion  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

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

    /* Buffers */
    uint8_t read_buffer_mem[2048], write_buffer_mem[2048];
    buffer read_buffer, write_buffer;
};

#endif