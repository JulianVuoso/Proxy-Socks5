#ifndef REQUEST_H_da39a3ee5e6b4b0d3255bfef95601890afd80709
#define REQUEST_H_da39a3ee5e6b4b0d3255bfef95601890afd80709

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"

#define REQUEST_ADDRESS_TYPE_IPV4 0x01
#define REQUEST_ADDRESS_TYPE_NAME 0x03
#define REQUEST_ADDRESS_TYPE_IPV6 0x04

static const uint8_t REQUEST_COMMAND_CONNECT = 0x01;

static const uint8_t REQUEST_RESPONSE_SUCCESS = 0x00;
static const uint8_t REQUEST_RESPONSE_NET_UNREACH = 0x03;
static const uint8_t REQUEST_RESPONSE_HOST_UNREACH = 0x04;
static const uint8_t REQUEST_RESPONSE_CON_REFUSED = 0x05;
static const uint8_t REQUEST_RESPONSE_TTL_EXPIRED = 0x06;
static const uint8_t REQUEST_RESPONSE_CMD_NOT_SUP = 0x07;
static const uint8_t REQUEST_RESPONSE_ADD_TYPE_NOT_SUP = 0x08;

/*
    The SOCKS request is formed as follows:
    +----+-----+-------+------+----------+----------+
    |VER | CMD | RSV   | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X’00’ |  1   | Variable |     2    |
    +----+-----+-------+------+----------+----------+
    Where:
    - VER -> protocol version: X’05’
    - CMD
        - CONNECT X’01’
        - BIND X’02’
        - UDP ASSOCIATE X’03’
    - RSV -> RESERVED
    - ATYP -> address type of following address
        - IP V4 address: X’01’
        - DOMAINNAME: X’03’
        - IP V6 address: X’04’
    - DST.ADDR -> desired destination address
    - DST.PORT -> desired destination port in network octet order
*/

/* Estados del parser del request */
enum request_state {
    request_version,
    request_command,
    request_reserved,
    request_address_type,
    request_address_data,
    request_port,
    request_done,
    request_error
};

/* Errores del parser del request */
enum request_errors {
    error_request_no_error,
    error_request_unsupported_version,
    error_request_unsupported_command,
    error_request_invalid_reserved_byte,
    error_request_invalid_address_type,
    error_request_invalid_fqdn_length,
    error_request_no_more_heap,
};

enum address_types {
    address_ipv4,
    address_fqdn,
    address_ipv6,
};

// Set initial port to determine if its first or second byte
static const uint16_t INITIAL_PORT = 1;

typedef struct destination {
    enum address_types address_type;
    uint8_t * address; // \0 Terminated String (pero tengo el size)
    uint8_t address_length;
    uint8_t address_index;
    uint16_t port;
} destination;

/* TODO: Ver que mas va aca */
typedef struct request_parser {
    enum request_state state;
    enum request_errors error;
    struct destination * dest;
} request_parser;

/** inicializa el parser */
void request_parser_init (struct request_parser *p);

/** entrega un byte al parser, retorna estado al salir  */
enum request_state 
request_parser_feed (struct request_parser *p, uint8_t byte);

/**
 * por cada elemento del buffer llama a request_parser_feed hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum request_state
request_consume(buffer *b, struct request_parser *p, bool *errored);

/**
 * Permite distinguir a quien usa request_parser_feed si debe seguir
 * enviando caracters o no. 
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool 
request_is_done(const enum request_state state, bool *errored);

/* Si llego a un estado de error, permite obtener la representacion
   textual que describe el problema */
const char *
request_error_description(const struct request_parser *p);

/** libera recursos internos del parser */
void request_parser_close(struct request_parser *p);

/**
 * serializa en buff la una respuesta al request.
 *
 * Retorna la cantidad de bytes ocupados del buffer o -1 si no había
 * espacio suficiente.
 */
int
request_marshall(buffer *b, uint8_t status, enum address_types type);

#endif