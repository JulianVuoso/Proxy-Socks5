#include <stdio.h>
#include <stdlib.h> // malloc

#include "request.h"

void request_parser_init (request_parser * p) {
    p->state = request_version;   
    p->error = error_request_no_error;
    p->dest = malloc(sizeof(*p->dest));
    if (p->dest == NULL) {
        p->error = error_request_no_more_heap;
        p->state = request_error;
        return;
    }
    p->dest->address = NULL;
    p->dest->address_length = 0;
    p->dest->address_index = 0;
    p->dest->address_type = address_ipv4;
    p->dest->port = INITIAL_PORT;
}

static void solve_address_type(request_parser * p, uint8_t byte) {
    switch (byte)
    {
        case REQUEST_ADDRESS_TYPE_IPV4:
            p->dest->address_type = address_ipv4;
            p->dest->address_length = 4;
            p->state = request_address_data;
            break;
        case REQUEST_ADDRESS_TYPE_NAME:
            p->dest->address_type = address_fqdn;
            p->dest->address_length = 0;
            p->state = request_address_data;
            break;
        case REQUEST_ADDRESS_TYPE_IPV6:
            p->dest->address_type = address_ipv6;
            p->dest->address_length = 16;
            p->state = request_address_data;
            break;
        default: // Error
            p->error = error_request_invalid_address_type;
            p->state = request_error;
            break;
    }
}

enum request_state
request_parser_feed (request_parser * p, uint8_t byte) {
    switch (p->state)
    {
        case request_version:
            if (byte == 0x05) {
                p->state = request_command;
            } else {
                p->error = error_request_unsupported_version;
                p->state = request_error;
            }
            break;
        case request_command:
            if (byte == REQUEST_COMMAND_CONNECT) {
                p->state = request_reserved;
            } else {
                p->error = error_request_unsupported_command;
                p->state = request_error;
            }
            break;
        case request_reserved:
            if (byte == 0x00) {
                p->state = request_address_type;
            } else {
                p->error = error_request_invalid_reserved_byte;
                p->state = request_error;
            }
            break;
        case request_address_type:
            solve_address_type(p, byte);
            break;
        case request_address_data:
            if (p->dest->address == NULL) {
                if (p->dest->address_type == address_fqdn && p->dest->address_length == 0) {
                    p->dest->address_length = byte;
                    if (byte == 0) {
                        p->error = error_request_invalid_fqdn_length;
                        p->state = request_error;
                    }
                    break;
                }
                // p->dest->address_length NO puede ser cero
                p->dest->address_index = 0;
                p->dest->address = malloc(sizeof(*p->dest->address) * (p->dest->address_length + 1));
                if (p->dest->address == NULL) {
                    p->error = error_request_no_more_heap;
                    p->state = request_error;
                }
            }
            p->dest->address[p->dest->address_index++] = byte;
            p->dest->address_length--;
            if (p->dest->address_length == 0) {
                p->dest->address[p->dest->address_index] = '\0';
                p->dest->address_length = p->dest->address_index;
                p->dest->address_index = 0;
                p->state = request_port;
            }
            break;
        case request_port:
            if (p->dest->port == INITIAL_PORT) {
                // El puerto queda en 0 o en >= 256
                p->dest->port = (byte << 8);
            } else {
                p->dest->port += byte;
                p->state = request_done;
            }
            break;
        case request_done:
        case request_error:
            /* Nada que hacer */
            break;        
        default:
            fprintf(stderr, "unknown state %d\n", p->state);
            abort();
    }

    return p->state;
}

enum request_state
request_consume(buffer *b, struct request_parser *p, bool *errored) {
    enum request_state state = p->state;
    
    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        state = request_parser_feed(p, c);
        if (request_is_done(state, errored)) {
            break;
        }
    }
    return state;
}

bool 
request_is_done(const enum request_state state, bool *errored) {
    bool ret;
    switch (state)
    {
        case request_error:
            if (errored != NULL) {
                *errored = true;
            }
            ret = true;
            break;
        case request_done:
            if (errored != NULL) {
                *errored = false;
            }
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
    return ret;
}

const char *
request_error_description(const struct request_parser *p) {
    char *ret;
    switch (p->error)
    {
        case error_request_unsupported_version:
            ret = "unsupported version";
            break;
        case error_request_unsupported_command:
            ret = "unsupported command";
            break;
        case error_request_invalid_reserved_byte:
            ret = "invalid reserved bytes";
            break;
        case error_request_invalid_address_type:
            ret = "invalid address type";
            break;
        case error_request_invalid_fqdn_length:
            ret = "invalid fqdn length";
            break;
        case error_request_no_more_heap:
            ret = "could not allocate memory";
            break;
        default:
            ret = "";
            break;
    }
    return ret;
}

uint8_t
request_reply_code(const struct request_parser * p) {
    uint8_t ret;
    switch (p->error)
    {
        case error_request_unsupported_version:
        case error_request_invalid_reserved_byte:
        case error_request_invalid_fqdn_length:
        case error_request_no_more_heap:
            ret = REQUEST_RESPONSE_GEN_SOCK_FAIL;
            break;
        case error_request_unsupported_command:
            ret = REQUEST_RESPONSE_CMD_NOT_SUP;
            break;
        case error_request_invalid_address_type:
            ret = REQUEST_RESPONSE_ADD_TYPE_NOT_SUP;
            break;
        default:
            ret = REQUEST_RESPONSE_SUCCESS;
            break;
    }
    return ret;
}

const char *
request_reply_code_description(uint8_t reply_code) {
    char * ret;
    switch (reply_code)
    {
        case REQUEST_RESPONSE_SUCCESS:
            ret = "successfull request";
            break;
        case REQUEST_RESPONSE_GEN_SOCK_FAIL:
            ret = "general SOCKS server failure";
            break;
        case REQUEST_RESPONSE_CON_NOT_ALL_RULESET:
            ret = "connection not allowed by ruleset";
            break;
        case REQUEST_RESPONSE_NET_UNREACH:
            ret = "network unreachable";
            break;
        case REQUEST_RESPONSE_HOST_UNREACH:
            ret = "host unreachable";
            break;
        case REQUEST_RESPONSE_CON_REFUSED:
            ret = "connection refused";
            break;
        case REQUEST_RESPONSE_TTL_EXPIRED:
            ret = "TTL expired";
            break;
        case REQUEST_RESPONSE_CMD_NOT_SUP:
            ret = "command not supported";
            break;
        case REQUEST_RESPONSE_ADD_TYPE_NOT_SUP:
            ret = "address type not supported";
            break;
        default:
            ret = "unknown reply code";
            break;
    }
    return ret;
}

void request_parser_close(struct request_parser *p) {
    if (p != NULL) {
        free(p->dest->address);
        free(p->dest);
    }
}

int
request_marshall(buffer *b, uint8_t status, enum address_types type) {
    size_t n;
    uint8_t * buff = buffer_write_ptr(b, &n);
    size_t addr_size, addr_type;
    switch (type)
    {
        case address_ipv6:
            addr_size = 16;
            addr_type = REQUEST_ADDRESS_TYPE_IPV6;
            break;
        default: // address_ipv4 or other
            addr_size = 4;
            addr_type = REQUEST_ADDRESS_TYPE_IPV4;
            break;
    }
    if (n < (6 + addr_size)) {
        return -1;
    }
    uint8_t index = 0;
    buff[index++] = 0x05;
    buff[index++] = status;
    buff[index++] = 0x00;
    buff[index++] = addr_type;
    for (uint8_t j = 0; j < addr_size; j++) {
        buff[index++] = 0; // Bind address
    }
    buff[index++] = 0; buff[index++] = 0; // Bind port
    buffer_write_adv(b, 6 + addr_size);
    return 6 + addr_size;
}