#ifndef NEGOTIATION_H_da39a3ee5e6b4b0d3255bfef95601890afd80709
#define NEGOTIATION_H_da39a3ee5e6b4b0d3255bfef95601890afd80709

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#include "users.h"

static const uint8_t NEGOT_RESPONSE_SUCCESS = 0x00;
static const uint8_t NEGOT_RESPONSE_ERROR = 0x01;

/*
    The SOCKS negotiation is formed as follows:

    +-----+------+----------+------+------------+
    | VER | ULEN |   UNAME  | PLEN |   PASSWD   |
    +-----+------+----------+------+------------+
    |  1  |  1   | 1 to 255 |   1  |  1 to 255  |
    +-----+------+----------+------+------------+

    Where: 
    - VER    -> current version of the subnegotiation: X’01’. 
    - ULEN   -> length of the UNAME field
    - UNAME  -> username as known to the source OS
    - PLEN   -> length of the PASSWD field that follows
    - PASSWD -> password associated with the given UNAME.
*/

/* Estados del parser de negotiation */
enum negot_state {
    negot_version,
    negot_ulen,
    negot_uname,
    negot_plen,
    negot_passwd,
    negot_done,
    negot_error
};

enum negot_errors {
    error_negot_no_error,
    error_negot_unsupported_version,
    error_negot_invalid_ulen,
    error_negot_invalid_uname,
    error_negot_invalid_plen,
    error_negot_invalid_passwd,
    error_negot_no_more_heap,
};

typedef struct negot_parser {
    enum negot_state state;
    enum negot_errors error;
    struct negot_username * username;
    struct negot_password * password;
} negot_parser;

typedef struct negot_username {
    uint8_t ulen;
    uint8_t * uname;
    uint8_t index;
} negot_username;

typedef struct negot_password {
    uint8_t plen;
    uint8_t * passwd;
    uint8_t index;
} negot_password;


/** inicializa el parser */
void negot_parser_init(negot_parser *p);

/**
 * Por cada elemento del buffer llama a negot_parser_feed hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 * 
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum negot_state
negot_consume(buffer *b, struct negot_parser *p, bool *errored);

/** entrega un byte al parser, retorna estado al salir  */
enum negot_state
negot_parser_feed (negot_parser * p, uint8_t byte);

/* Si llego a un estado de error, permite obtener la representacion
   textual que describe el problema */
const char *
negot_error_description(const struct negot_parser *p);

/**
 * Permite distinguir a quien usa negot_parser_feed si debe seguir
 * enviando caracters o no. 
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool 
negot_is_done(const enum negot_state state, bool *errored);

/** libera recursos internos del parser */
void 
negot_parser_close(struct negot_parser *p);

extern int 
negot_marshall(buffer *b, uint8_t status);

#endif