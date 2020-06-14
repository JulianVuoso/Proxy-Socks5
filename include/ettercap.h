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
    ettercap_error_pop3_
} ettercap_errors;

typedef struct ettercap_username {
    uint8_t ulen;
    uint8_t * uname;
    uint8_t index;
} ettercap_username;

typedef struct ettercap_password {
    uint8_t plen;
    uint8_t * passwd;
    uint8_t index;
} ettercap_password;

typedef struct ettercap_parser {
    ettercap_state state;
    ettercap_errors error;
    ettercap_username * username;
    ettercap_password * password;
} ettercap_parser;


#endif