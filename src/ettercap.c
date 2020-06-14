/**
 * ettercap.c -- parser del ettercap (robado de credenciales)
 */
#include <stdio.h>
#include <stdlib.h>

#include "ettercap.h"


void
ettercap_parser_init(ettercap_parser * p, uint64_t port) {
    if (port == 110)
        p->state = ettercap_pop3_server_ok;
    else 
        p->state = ettercap_http_get;
    p->error = ettercap_error_none;
    p->username = calloc(1, sizeof(*p->username));
    p->password = calloc(1, sizeof(*p->password));
    if (p->username == NULL || p->password == NULL) {
        p->error = ettercap_error_heap_full;
        p->state = ettercap_error;
        return;
    }
}



ettercap_state
ettercap_consume_client(buffer * b, ettercap_parser * p, bool * errored) {
    ettercap_state state = p->state;
    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read_not_adv(b);
        state = ettercap_parser_client_feed(p, c);
        if (ettercap_is_done(state, errored)) break;
    }
    return state;
}

ettercap_state
ettercap_consume_server(buffer * b, ettercap_parser * p, bool * errored) {
    ettercap_state state = p->state;
    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read_not_adv(b);
        state = ettercap_parser_server_feed(p, c);
        if (ettercap_is_done(state, errored)) break;
    }
    return state;
}

const char *
ettercap_error_desc(const ettercap_parser * p) {
    char * ret;
    switch (p->error) {
    case ettercap_error_heap_full:
        ret = "could not allocate memory";
        break;
    default:
        ret = "";
        break;
    }  
    return ret; 
}

bool
ettercap_is_done(const ettercap_state state, bool * errored) {
    bool ret;
    switch (state) {
        case ettercap_error:
            if (errored != NULL) *errored = true;
            ret = true;
            break;
        case ettercap_done:
            if (errored != NULL) *errored = false;
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
    return ret;
}

void
ettercap_parser_close(ettercap_parser * p) {
    if (p == NULL) return;
    free(p->username->uname);
    free(p->username);
    free(p->password->passwd);
    free(p->password);
}