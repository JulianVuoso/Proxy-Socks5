/**
 * ettercap.c -- parser del ettercap (robado de credenciales)
 */
#include <stdio.h>
#include <stdlib.h>

#include "ettercap.h"


void
ettercap_parser_init(ettercap_parser * p, uint64_t port) {
    if (port == POP3_PORT)
        p->state = ettercap_pop3_command;
    else 
        p->state = ettercap_http_get;
    p->error = ettercap_error_none;

    /** Initialize credentials on null */
    p->username = NULL;
    p->password = NULL;
    p->usernames = NULL;
    p->passwords = NULL;
    p->validations = NULL;
    p->client_word = NULL;
    p->server_word = NULL;   
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


ettercap_state
ettercap_parser_feed_client(ettercap_parser * p, uint8_t byte) {
    switch (p->state) {
        case ettercap_http_get:
            /* TODO: save until ' ', on ' ' check if string === GET, then goto ettercap_http_path */
            break;
        case ettercap_http_path:
            /* TODO: check first is a / then until ' ' do nothing, on ' ' goto ettercap_http_vers */
            break;
        case ettercap_http_vers:
            /* TODO: save until ' ', on ' ' check if string == HTPP/1.1, then goto ettercap_http_headers */
            break;
        case ettercap_http_headers:
            /* TODO: save until ' ', == authenticate?, yes goto ettercap_authenticate 
                no goto ettercap_http_wait_end           
            */
            break;
        case ettercap_http_wait_end:
            /* TODO: wait till end of line '\r\n' if end of line and empty string -> done */
            break;
        case ettercap_http_basic:
            /* TODO: now  comes Basic and then credentials, until ' ', if == Basic goto ettercap_http_credentials */
            break;
        case ettercap_http_user:
            /* TODO read decoded user until : and save, on ':' goto ettercap_http_pass */
            break;
        case ettercap_http_pass:
            /* TODO read and save decoded pass */
            break;

        case ettercap_pop3_command:
            /* TODO  read until ' ', if user goto _pop3_user, if pass goto _pop3_pass*/
            break;
        case ettercap_pop3_user:
            /* TODO read until '\n' and save on new index of array or the same if prev pass empty, goto command */
            break;
        case ettercap_pop3_pass:
            /* TODO read until '\n' and save on current index of array goto command */
            break;
        
    }
}

ettercap_state
ettercap_parser_feed_server(ettercap_parser * p, uint8_t byte) {
    switch (p->state) {
        case ettercap_pop3_command:
        case ettercap_pop3_user:
        case ettercap_pop3_pass:
            /* TODO wait until ' ', if +OK on -ERR */
            break;
            
        default:
            /* all the HTTPs responses, do nothing */
            break;
    }
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
    // TODO free
}