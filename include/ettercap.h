#ifndef ETTERCAP_H_
#define ETTERCAP_H_

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"


#define WORD_BLOCK 5

#define HTTP_GET_SIZE 3
#define HTTP_VERS_SIZE 8
#define HTTP_PORT 80

#define HTTP_GET "get"
#define HTTP_VERS "http/1.1"
#define HTTP_AUTH "authorization:"
#define HTTP_BASIC "basic"


#define POP3_BLOCK 5
#define POP3_CMD_MAX 4

#define POP3_PORT 110
#define POP3_USER "user"
#define POP3_PASS "pass"

/*
 * HTTP client GET.
 * The only header of interest is the Authorization Basic, given it has user
 * and password in plain text (encoded in base64). Other methods are not 
 * supported for credentials sniffing (in this proxy server). 
 * The HTTP GET syntax
 * 
 * -----------  Start GET  -----------
 * GET /[path] HTTP/[version]\r\n
 * X-HEADER: X-Value\r\n
 *      .
 *      .
 *      .
 * Authorization: Basic <credentials>\r\n
 *      .
 *      .
 *      .
 * \r\n
 * -----------  End GET  -----------
 * 
 * 
 * POP3 client authorization fase syntax:
 * 
 * -----------  Start Clean Login  -----------
 * +OK [greating] ready.\r\n
 * user <username>\n
 * +OK\r\n
 * pass <password>\n
 * +OK Logged in.\r\n
 * -----------  End Clean Login  -----------
 * 
 * ERRORS: 
 * -ERR Unknow command.\r\n
 * -ERR [AUTH] Authentication failed.\r\n
 * 
 * NOTES: 
 *      - Use the last user entered by the user.
 *      - After error on authentication re enter user + password.
 *      - Client could write while waiting for server answer. CHECK!
 *          
 */

typedef enum ettercap_state {   
    ettercap_http_get,
    ettercap_http_path,
    ettercap_http_vers,
    ettercap_http_headers,
    ettercap_http_wait_cr,
    ettercap_http_lf,
    ettercap_http_basic,
    ettercap_http_credentials,

    ettercap_pop3_command,
    ettercap_pop3_user,
    ettercap_pop3_pass,
    ettercap_pop3_wait_end,

    ettercap_done,
    ettercap_error,
} ettercap_state;

typedef enum ettercap_errors {
    ettercap_error_none,
    ettercap_error_heap_full,

    ettercap_error_http_invalid,
    ettercap_error_http_no_get,
    ettercap_error_http_no_auth,
    ettercap_error_http_bad_auth,
} ettercap_errors;

typedef struct ettercap_word {
    uint8_t * value;
    uint8_t index;
    uint8_t length;
} ettercap_word;


/** Parser data struct */
typedef struct ettercap_parser {
    /** Current parser state */
    ettercap_state state;
    /** Parser errors */
    ettercap_errors error;

    /** Stolen credentials */
    uint8_t * username;
    uint8_t * password;

    /** For parser buffering words */
    ettercap_word * aux_word;
} ettercap_parser;



/** Initialize parser, sends corresponding port number */
void 
ettercap_parser_init(ettercap_parser * p, uint64_t port);


/**
 * Consumes one byte on the actual parser. Client side parser.
 */
ettercap_state 
ettercap_parser_feed(ettercap_parser * p, uint8_t b);


/**
 * For each element of buffer calls 'ettercap_parser_client_feed' until
 * parsing is done or more bytes are required.
 * 
 * @param errored out param. If different from NULL then the parser must
 * have an error.
 */
ettercap_state 
ettercap_consume(buffer * b, ettercap_parser * p, bool * errored);



/**
 * Allows to get a full representation of the error reached (if reached).
 */
const char *
ettercap_error_desc(const ettercap_parser * p);


/**
 * Checks if the parser is finished processing information.
 * In the event of an error, it is returned on @param errored.
 */
bool
ettercap_is_done(const ettercap_state state, bool * errored);


/**
 * Frees all the resources used by the parser.
 */
void
ettercap_parser_close(ettercap_parser * p);

#endif