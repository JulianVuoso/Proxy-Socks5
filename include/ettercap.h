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
 * The HTTP GET sintax
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
 * +OK Dovecot [(Ubuntu)] ready.\r\n
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
 *      - Error on authentication allows to re enter only password.
 *      - Errors does not delete last user added.
 *          
 */

#endif