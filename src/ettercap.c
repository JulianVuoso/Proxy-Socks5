/**
 * ettercap.c -- parser del ettercap (robado de credenciales)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "ettercap.h"

/* Auxiliar fucntions */
void ettercap_word_add_byte(ettercap_parser * p, ettercap_word * word, uint8_t byte);
void ettercap_word_clear(ettercap_word * word);
void ettercap_add_username(ettercap_parser * p, ettercap_word * word);
void ettercap_add_password(ettercap_parser * p, ettercap_word * word);


void
ettercap_parser_init(ettercap_parser * p, uint64_t port) {
    if (port == POP3_PORT) 
        p->state = ettercap_pop3_command;
    else 
        p->state = ettercap_http_get;
    p->error = ettercap_error_none;
    p->username = NULL;
    p->password = NULL;

    /** Initialize credentials on null */
    p->aux_word = calloc(1, sizeof(ettercap_word));
    if (p->aux_word == NULL) {
        p->state = ettercap_error;
        p->error = ettercap_error_heap_full;
        return;
    }  
}


ettercap_state
ettercap_consume(buffer * b, ettercap_parser * p, bool * errored) {
    ettercap_state state = p->state;
    uint8_t i = 0;
    while (buffer_can_read_not_adv(b, i)) {
        const uint8_t c = buffer_read_not_adv(b, i++);
        state = ettercap_parser_feed(p, c);
        if (ettercap_is_done(state, errored)) break;
    }
    return state;
}



ettercap_state
ettercap_parser_feed(ettercap_parser * p, uint8_t byte) {
    switch (p->state) {
        case ettercap_http_get:
            /* Checks the HTTP GET action */
            if (byte == ' ') {
                if (strcmp((char *) p->aux_word->value, HTTP_GET) == 0) {
                    p->state = ettercap_http_path;
                    ettercap_word_clear(p->aux_word);
                } else {
                    p->state = ettercap_error;
                    p->error = ettercap_error_http_no_get;
                }
            } else if (p->aux_word->index >= HTTP_GET_SIZE) {
                p->state = ettercap_error;
                p->error = ettercap_error_http_no_get;
            } else 
                ettercap_word_add_byte(p, p->aux_word, tolower(byte));
            break;
        
        case ettercap_http_path:
            /* Wait for the path to pass */
            if (byte == ' ') {
                p->state = ettercap_http_vers;
            }
            break;

        case ettercap_http_vers:
            /* Checks the HTTP version */
            if (byte == '\r') {
                if (strcmp((char *) p->aux_word->value, HTTP_VERS) == 0) {
                    p->state = ettercap_http_lf;
                } else {
                    p->state = ettercap_error;
                    p->error = ettercap_error_http_invalid;
                }
            } else if (p->aux_word->index >= HTTP_VERS_SIZE) {
                p->state = ettercap_error;
                p->error = ettercap_error_http_invalid;
            } else 
                ettercap_word_add_byte(p, p->aux_word, tolower(byte));
            break;

        case ettercap_http_headers:
            /* Checks for authorization header */
            if (byte == ' ') {
                if (strcmp((char *) p->aux_word->value, HTTP_AUTH) == 0) {
                    p->state = ettercap_http_basic;
                    ettercap_word_clear(p->aux_word);
                } else
                    p->state = ettercap_http_wait_cr;
            } else if (byte == '\r') {
                p->state = ettercap_error;
                p->error = ettercap_error_http_no_auth;
            } else
                ettercap_word_add_byte(p, p->aux_word, tolower(byte));
            break;

        case ettercap_http_wait_cr:
            if (byte == '\r') p->state = ettercap_http_lf;
            break;

        case ettercap_http_lf:
            /* Next has to be '\n' */
            if (byte == '\n') {
                p->state = ettercap_http_headers;
                ettercap_word_clear(p->aux_word);
            } else {
                p->state = ettercap_error;
                p->error = ettercap_error_http_invalid;
            }
            break;

        case ettercap_http_basic:
            /* Checks authorization type */
            if (byte == ' ') {
                if (strcmp((char *) p->aux_word->value, HTTP_BASIC) == 0) {
                    p->state = ettercap_http_credentials;
                    ettercap_word_clear(p->aux_word);
                } else {
                    p->state = ettercap_error;
                    p->error = ettercap_error_http_bad_auth;
                }
            } else if (byte == '\r') {
                p->state = ettercap_error;
                p->error = ettercap_error_http_bad_auth;
            } else
                ettercap_word_add_byte(p, p->aux_word, tolower(byte));
            break;
        
        case ettercap_http_credentials:
            /* Get encoded credentials */
            if (byte == '\r') {
                p->state = ettercap_done;
                ettercap_add_username(p, p->aux_word);
            } else 
                ettercap_word_add_byte(p, p->aux_word, byte);
            break;



        case ettercap_pop3_command:
            /* Waits for word user or pass */
            if (byte == ' ') {
                if (strcmp((char *) p->aux_word->value, POP3_USER) == 0)
                    p->state = ettercap_pop3_user;
                else if (strcmp((char *) p->aux_word->value, POP3_PASS) == 0)
                    p->state = ettercap_pop3_pass;
                else 
                    p->state = ettercap_pop3_wait_end;
                ettercap_word_clear(p->aux_word);
            } else if (p->aux_word->index >= POP3_CMD_MAX)
                p->state = ettercap_pop3_wait_end;
            else
                ettercap_word_add_byte(p, p->aux_word, tolower(byte));
            break;

        case ettercap_pop3_user:
            /* Reads username and saves */
            if (byte == '\n') {
                p->state = ettercap_pop3_command;
                ettercap_add_username(p, p->aux_word);
                ettercap_word_clear(p->aux_word);
            } else
                ettercap_word_add_byte(p, p->aux_word, byte);
            break;

        case ettercap_pop3_pass:
            /* Reads password and saves */
            if (byte == '\n') {
                p->state = ettercap_done;
                ettercap_add_password(p, p->aux_word);
                ettercap_word_clear(p->aux_word);
            } else
                ettercap_word_add_byte(p, p->aux_word, byte);
            break;

        case ettercap_pop3_wait_end:
            /* Waits until end of line */
            if (byte == '\n') {
                p->state = ettercap_pop3_command;
                ettercap_word_clear(p->aux_word);
            }
            break;
        case ettercap_done:
        case ettercap_error:
            /* Nothing to do here */
            break;        
        default:
            fprintf(stderr, "unknown state %d\n", p->state);
            abort();
    }
    return p->state;
}

const char *
ettercap_error_desc(const ettercap_parser * p) {
    char * ret;
    switch (p->error) {
    case ettercap_error_heap_full:
        ret = "could not allocate memory";
        break;
    case ettercap_error_http_invalid:
        ret = "invalid http format";
        break;
    case ettercap_error_http_no_get:
        ret = "http request is not GET";
        break;
    case ettercap_error_http_no_auth:
        ret = "http request does not have authorization header";
        break;
    case ettercap_error_http_bad_auth:
        ret = "http bad authorization header format";
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
    free(p->aux_word->value);
    free(p->aux_word);
    if (p->username != NULL) free(p->username);
    if (p->password != NULL) free(p->password);
}


/* Auxiliary private functions */

void 
ettercap_word_add_byte(ettercap_parser * p, ettercap_word * word, uint8_t byte) {
    if (word->index >= word->length - 1) {
        word->length += WORD_BLOCK;
        word->value = realloc(word->value, word->length);
        if (word->value == NULL) {
            p->state = ettercap_error;
            p->error = ettercap_error_heap_full;
            return;
        }         
    }
    word->value[word->index++] =  byte;
    word->value[word->index] = '\0';
}

void
ettercap_word_clear(ettercap_word * word) {
    word->index = 0;
    word->value[0] = '\0';
}

void
ettercap_add_username(ettercap_parser * p, ettercap_word * word) {
    p->username = realloc(p->username, word->index + 1);
    if (p->username == NULL) {
        p->state = ettercap_error;
        p->error = ettercap_error_heap_full;
    }
    for (uint8_t i = 0; i <= word->index; i++)
        p->username[i] = word->value[i];
}

void
ettercap_add_password(ettercap_parser * p, ettercap_word * word) {
    p->password = realloc(p->password, word->index + 1);
    if (p->password == NULL) {
        p->state = ettercap_error;
        p->error = ettercap_error_heap_full;
    }
    for (uint8_t i = 0; i <= word->index; i++)
        p->password[i] = word->value[i];
}