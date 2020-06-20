#ifndef ADMINMT_H_87e20525d124aa802c84c02993a112a05ca55e8f
#define ADMINMT_H_87e20525d124aa802c84c02993a112a05ca55e8f

#include <sys/socket.h>
#include "stm.h"
#include "selector.h"
#include "buffer.h"

#include "admin_sm_negot_state.h"
#include "admin_sm_cmd_state.h"

enum admin_state {
    /**
     * recibe el mensaje de autenticacion del cliente.
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - ADMIN_NEGOT_READ     mientras el mensaje no esta completo
     *   - ADMIN_NEGOT_WRITE    cuando esta completo
     *   - ERROR                ante cualquier error (IO/parseo)
     */
    ADMIN_NEGOT_READ,

    /**
     * envi­a la respuesta de la autenticacion al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - ADMIN_NEGOT_WRITE    mientras queden bytes por enviar
     *   - ADMIN_CMD_READ       cuando se enviaron todos los bytes
     *   - ERROR                ante cualquier error (IO/parseo/credenciales)
     */
    ADMIN_NEGOT_WRITE,

    /**
     * recibe un request del cliente y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - ADMIN_CMD_READ   mientras el request no esta completo
     *   - ADMIN_CMD_WRITE  si se termino de leer
     *   - DONE             si el cliente cerro la conexion y no queda nada por enviar
     *   - ERROR            ante cualquier error (IO/parseo)
     */
    ADMIN_CMD_READ,

    /**
     * escribe la respuesta del request al cliente
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - ADMIN_CMD_WRITE  mientras queden bytes por enviar
     *   - DONE             si el cliente cerro la conexion y no queda nada por enviar
     *   - ERROR            por error de I/O
     */
    ADMIN_CMD_WRITE,

    /* Estado terminal exitoso */
    ADMIN_DONE,

    /* Estado terminal sin exito */
    ADMIN_ERROR,
};

static const struct state_definition admin_statbl[] = {
    {
        .state            = ADMIN_NEGOT_READ,
        .on_arrival       = admin_negot_read_init,
        .on_departure     = admin_negot_read_close,
        .on_read_ready    = admin_negot_read,
    },
    {
        .state            = ADMIN_NEGOT_WRITE,
        .on_arrival       = admin_negot_write_init,
        .on_departure     = admin_negot_write_close,
        .on_write_ready   = admin_negot_write,
    },
    {
        .state            = ADMIN_CMD_READ,
        .on_arrival       = admin_cmd_read_init,
        .on_departure     = admin_cmd_read_close,
        .on_read_ready    = admin_cmd_read,
    },
    {
        .state            = ADMIN_CMD_WRITE,
        .on_arrival       = admin_cmd_write_init,
        .on_departure     = admin_cmd_write_close,
        .on_write_ready   = admin_cmd_write,
    },
    {
        .state            = ADMIN_DONE,
    },
    {
        .state            = ADMIN_ERROR,
    },
};

/** obtiene el struct (admin *) desde la llave de seleccion  */
#define ADMIN_ATTACH(key) ( (struct admin *)(key)->data)

#define ADMIN_BUF_SIZE 4096

struct admin {
    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el cliente */
    union {
        struct admin_negot_st   negot;
        // struct admin_cmd_st     cmd;
    } client;

    /* Informacion del cliente */
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_fd;

    /* Buffers */
    uint8_t read_buffer_mem[ADMIN_BUF_SIZE], write_buffer_mem[ADMIN_BUF_SIZE];
    buffer read_buffer, write_buffer;

    /* Proxy Server fd to update interest if needed when destroyed */
    int proxy_fd;
};

#endif