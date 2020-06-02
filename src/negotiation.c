#include <stdio.h>
#include <stdlib.h> // malloc

#include "negotiation.h"

void 
negot_parser_init(negot_parser *p)
{
    p->state = negot_version;
    p->error = error_negot_no_error;
    p->username->ulen = 0;
    p->username->uname = NULL; 
    p->username->index = 0;
    p->password->plen = 0;
    p->password->passwd = NULL;  
    p->password->index = 0;
}

enum negot_state
negot_consume(buffer *b, struct negot_parser *p, bool *errored) {
    enum negot_state state = p->state;
    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        state = negot_parser_feed(p, c);
        if (negot_is_done(state, errored))
            break;
    }
    return state;
}

enum negot_state
negot_parser_feed (negot_parser * p, uint8_t byte) {
    switch (p->state)
    {
        case negot_version:
            if (byte == 0x01) {
                p->state = negot_ulen;
            } else {
                p->error = error_negot_unsupported_version;
                p->state = negot_error;
            }
            break;
        case negot_ulen:
            if (byte > -1) { // ver cual seria un uname erroneo 
                p->username->ulen = byte;
                p->username->uname = malloc(sizeof(uint8_t) * (byte+1));
                p->state = negot_uname;
            } else {
                p->error = error_negot_invalid_ulen;
                p->state = negot_error;
            }
            break;
        case negot_uname:
            if (byte > -1) { // ver cual seria un error
                p->username->ulen--;
                p->username->uname[p->username->index++] = byte;
                if(p->username->ulen == 0){
                    p->username->uname[index]='\0';
                    p->state = negot_plen;
                }
            } else {
                p->error = error_negot_invalid_uname;
                p->state = negot_error;
            }
            break;
        case negot_plen:
            if (byte > -1) {
                p->password->plen = b;
                p->password->passwd = malloc(sizeof(uint8_t) * (byte+1));
                p->state = negot_uname;
            } else {
                p->error = error_negot_invalid_plen;
                p->state = negot_error;
            }
            break;
        case negot_passwd:
            if (byte > -1) {
                p->password->plen--;
                p->password->passwd[p->password->index++] = byte;
                if(p->password->plen == 0){
                    p->password->passwd[index]='\0';
                    p->state = negot_done;
                }
            } else {
                p->error = error_negot_invalid_passwd;
                p->state = negot_error;
            }
            break;
        case negot_done:
        case negot_error:
            /* Nada que hacer */
            break;        
        default:
            fprintf(stderr, "unknown state %d\n", p->state);
            abort();
    }
    return p->state;
}

const char *
negot_error_description(const struct negot_parser *p) {
    char *ret;
    switch (p->error)
    {
        case error_negot_unsupported_version:
            ret = "unsupported version";
            break;
        case error_negot_invalid_ulen:
            ret = "unsupported command";
            break;
        case error_negot_invalid_uname:
            ret = "invalid reserved bytes";
            break;
        case error_negot_invalid_plen:
            ret = "invalid address type";
            break;
        case error_negot_invalid_passwd:
            ret = "invalid fqdn length";
            break;
        case error_negot_no_more_heap:
            ret = "could not allocate memory";
            break;
        default:
            ret = "";
            break;
    }
    return ret;
}

bool 
negot_is_done(const enum negot_state state, bool *errored) {

    bool ret;
    switch (state)
    {
        case negot_error:
            if (errored != NULL) {
                *errored = true;
            }
            ret = true;
            break;
        case negot_done:
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

void 
negot_parser_close(struct negot_parser *p) {
    if (p != NULL) {
        free(p->username->uname);
        free(p->password->passwd);
    }
}
