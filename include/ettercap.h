#ifndef ETTERCAP_H_
#define ETTERCAP_H_

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"

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
    ettercap_init,
    ettercap_http_get,
    ettercap_http_vers,
    ettercap_http_headers,
    ettercap_http_auth,
    ettercap_pop3_server_ok,
    ettercap_pop3_user,
    ettercap_pop3_pass,
    ettercap_done,
    ettercap_error,
} ettercap_state;

typedef enum ettercap_errors {
    ettercap_error_http_invalid,
    ettercap_error_pop3_, // TODO finish 
} ettercap_errors;

/** Usrename model */ // TODO might not be needed 
typedef struct ettercap_username {
    uint8_t ulen;
    uint8_t * uname;
    uint8_t index;
} ettercap_username;

/** Password model */ // TODO might not be needed 
typedef struct ettercap_password {
    uint8_t plen;
    uint8_t * passwd;
    uint8_t index;
} ettercap_password;

/** Parser data struct */
typedef struct ettercap_parser {
    /** Current parser state */
    ettercap_state state;
    /** Parser errors */
    ettercap_errors error;
    /** Stolen credentials */
    ettercap_username * username;
    ettercap_password * password;
} ettercap_parser;



/** Initialize parser */
void 
ettercap_parser_init(ettercap_parser * p);


/**
 * Consumes one byte on the actual parser. Client side parser.
 */
ettercap_state 
ettercap_parser_client_feed(ettercap_parser * p, uint8_t b);


/**
 * Consumes one byte on the actual parser. Server side parser.
 */
ettercap_state 
ettercap_parser_server_feed(ettercap_parser * p, uint8_t b);


/**
 * For each element of buffer calls 'ettercap_parser_client_feed' until
 * parsing is done or more bytes are required.
 * 
 * @param errored out param. If different from NULL then the parser must
 * have an error.
 */
ettercap_state 
ettercap_consume_client(buffer * b, ettercap_parser * p, bool * errored);


/**
 * For each element of buffer calls 'ettercap_parser_server_feed' until
 * parsing is done or more bytes are required.
 * 
 * @param errored out param. If different from NULL then the parser must
 * have an error.
 */
ettercap_state
ettercap_consume_server(buffer * b, ettercap_parser * p, bool * errored);


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