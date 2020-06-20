#ifndef HANDLERS_H_d4f12e31ae9fe3878d44027fdab552d63b292952
#define HANDLERS_H_d4f12e31ae9fe3878d44027fdab552d63b292952

#include <sys/socket.h>
#include "stm.h"
#include "selector.h"
#include "buffer.h"

#include "sm_hello_state.h"
#include "sm_negot_state.h"
#include "sm_request_state.h"
#include "sm_connect_state.h"
#include "sm_copy_state.h"
#include "doh_server_struct.h"

// Borrar cuando tenga su sm_state
// #include "negotiation.h"

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
     * envi­a la respuesta del 'hello' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - NEGOT_READ   cuando se enviaron todos los bytes
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
     *   - DNS_CONNECT      si esta completo, es un fqdn y estoy conectandome al doh_server
     *   - DNS_WRITE        si esta completo, es un fqdn y logre conectarmo al doh_server
     *   - DNS_SOLVE_BLK    si esta completo, es un fqdn y la conexion al doh_server fallo
     *   - REQUEST_CONNECT  si esta completo, NO es un fqdn y se puede 
     *                      establecer la conexion al origin server
     *   - REQUEST_WRITE    si hay un error de soporte de comando o similar
     *   - ERROR            ante cualquier error (IO/parseo)
     */
    REQUEST_READ,

    /**
     * Se espera a que la conexion con el doh server este establecida
     *
     * Intereses:
     *     - OP_NOOP sobre client_fd
     *     - OP_WRITE sobre doh_fd
     *
     * Transiciones:
     *   - DNS_WRITE        si la conexion es exitosa
     *   - DNS_SOLVE_BLK    si falla la conexion con el doh server
     */
    DNS_CONNECT,

    /**
     * Envia el request DNS al servidor DOH
     *
     * Intereses:
     *     - OP_NOOP sobre client_fd
     *     - OP_WRITE sobre doh_fd
     *
     * Transiciones:
     *   - DNS_WRITE    mientras queden bytes por enviar
     *   - DNS_READ     cuando el envio esta completo
     */
    DNS_WRITE,

    /**
     * Recibe la respuesta DNS del servidor DOH
     *
     * Intereses:
     *     - OP_NOOP sobre client_fd
     *     - OP_READ sobre doh_fd
     *
     * Transiciones:
     *   - DNS_READ         mientras queden bytes por leer
     *   - REQUEST_CONNECT  cuando el envio esta completo, intento establecer
     *                      la conexion con alguna de las direcciones
     *   - DNS_CONNECT      si no logro conectarme a ninguna direccion y
     *                      estoy en IPv4, intento con IPv6
     *   - DNS_SOLVE_BLK    si no logro conectarme a ninguna direccion y
     *                      estoy en IPv6, intento con getaddrinfo
     */
    DNS_READ,

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
    DNS_SOLVE_BLK,

    /**
     * Se espera a que la conexion este establecida
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

    /* Estado terminal exitoso */
    DONE,

    /* Estado terminal sin exito */
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
        .on_arrival       = negot_read_init,
        .on_departure     = negot_read_close,
        .on_read_ready    = negot_read,
    },
    {
        .state            = NEGOT_WRITE,
        .on_arrival       = negot_write_init,
        .on_departure     = negot_write_close,
        .on_write_ready   = negot_write,
    },
    {
        .state            = REQUEST_READ,
        .on_arrival       = request_read_init,
        .on_departure     = request_read_close,
        .on_read_ready    = request_read,
    },
    {
        .state            = DNS_CONNECT,
        .on_write_ready   = dns_connect_write,
    },
    {
        .state            = DNS_WRITE,
        .on_write_ready   = dns_write,
    },
    {
        .state            = DNS_READ,
        .on_arrival       = dns_read_init,
        .on_read_ready    = dns_read,
    },
    {
        .state            = DNS_SOLVE_BLK,
        .on_block_ready   = request_solve_block,
    },
    {
        .state            = REQUEST_CONNECT,
        .on_write_ready   = request_connect_write,
    },
    {
        .state            = REQUEST_WRITE,
        .on_arrival       = request_write_init,
        .on_departure     = request_close,
        .on_write_ready   = request_write,
    },
    {
        .state            = COPY,
        .on_arrival       = copy_init,
        .on_read_ready    = copy_read,
        .on_write_ready   = copy_write,
        .on_departure     = copy_close,
    },
    {
        .state            = DONE,
    },
    {
        .state            = ERROR,
        .on_arrival       = error_arrival,
    },
};

/** obtiene el struct (socks5 *) desde la llave de seleccion  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

#define INITIAL_BUF_SIZE 4096

enum connect_result {CON_OK, CON_ERROR, CON_INPROG};

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

    uint8_t * username;
    uint8_t username_length;

    /* Resolucion de la direc del origin server */
    struct sockaddr_storage origin_addr;
    socklen_t origin_addr_len;
    int origin_fd, origin_domain;
    char * fqdn;
    struct addrinfo * origin_resolution;
    enum connect_options option;

    /* Buffers */
    uint8_t read_buffer_mem[INITIAL_BUF_SIZE], write_buffer_mem[INITIAL_BUF_SIZE];
    buffer read_buffer, write_buffer;

    /* Reference count. If 1, it is destroyed */
    unsigned references;
    /* Proxy Server fd to update interest if needed when destroyed */
    int proxy_fd;
};

#endif