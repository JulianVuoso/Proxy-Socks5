#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/sctp.h>
#include <errno.h>

#include "adminmt.h"
#include "negotiation.h"
#include "logger.h"

void admin_negot_read_init(const unsigned state, struct selector_key *key) {
    struct admin_negot_st * st = &ADMIN_ATTACH(key)->client.negot;
    st->read_buf = &(ADMIN_ATTACH(key)->read_buffer);
    st->write_buf = &(ADMIN_ATTACH(key)->write_buffer);
    st->reply_code = NEGOT_RESPONSE_ERROR;
    negot_parser_init(&st->parser);
}
unsigned admin_negot_read(struct selector_key *key) {
    struct admin_negot_st * st_vars = &ADMIN_ATTACH(key)->client.negot;
    unsigned ret = ADMIN_NEGOT_READ;
    bool errored = false;
    size_t nbytes;
    uint8_t * buf_write_ptr = buffer_write_ptr(st_vars->read_buf, &nbytes);
    ssize_t n = sctp_recvmsg(key->fd, buf_write_ptr, nbytes, NULL, NULL, NULL, NULL);

    if (n > 0) {
        buffer_write_adv(st_vars->read_buf, n);
        const enum negot_state st = negot_consume(st_vars->read_buf, &st_vars->parser, &errored);
        if (negot_is_done(st, 0)) {
            if (selector_set_interest_key(key, OP_WRITE) == SELECTOR_SUCCESS) {
                ret = admin_negot_process(key);
            } else {
                ret = ADMIN_ERROR;
            }
        }
    } else {
        ret = ADMIN_ERROR;
    }

    return ret;
}
void admin_negot_read_close(const unsigned state, struct selector_key *key) {
    struct admin_negot_st * st = &ADMIN_ATTACH(key)->client.negot;
    negot_parser_close(&st->parser);
}

unsigned admin_negot_process(struct selector_key *key) {
    struct admin * admin = ADMIN_ATTACH(key);
    struct admin_negot_st * st_vars = &admin->client.negot;
    
    if (st_vars->parser.username == NULL || st_vars->parser.password == NULL) {
        st_vars->reply_code = NEGOT_RESPONSE_ERROR;
    } else {
        st_vars->reply_code = authenticate(st_vars->parser.username->uname, st_vars->parser.password->passwd, ADMIN);
    }
    
    if (negot_marshall(st_vars->write_buf, st_vars->reply_code) < 0)
        return ADMIN_ERROR;
    
    return ADMIN_NEGOT_WRITE;
}

void admin_negot_write_init(const unsigned state, struct selector_key *key) {
    /* Do nothing */
}

unsigned admin_negot_write(struct selector_key *key) {
    struct admin_negot_st * st_vars = &ADMIN_ATTACH(key)->client.negot;
    unsigned ret = ADMIN_NEGOT_WRITE;
    size_t nbytes;
    uint8_t * buf_read_ptr = buffer_read_ptr(st_vars->write_buf, &nbytes);
    ssize_t n = sctp_sendmsg(key->fd, buf_read_ptr, nbytes, NULL, 0, 0, 0, 0, 0, 0);

    if (n > 0) {
        buffer_read_adv(st_vars->write_buf, n);
        if (!buffer_can_read(st_vars->write_buf)) { // Termine de enviar el mensaje
            if (st_vars->reply_code == NEGOT_RESPONSE_SUCCESS) {
                logger_log(DEBUG, "Admin Negot OK\n");
                if (selector_set_interest_key(key, OP_READ) == SELECTOR_SUCCESS) {
                    ret = ADMIN_DONE; /** TODO: Change to ADMIN_CMD_READ  */
                } else {
                    ret = ADMIN_ERROR;
                }
            } else {
                logger_log(DEBUG, "Admin Negot failed\n");
                ret = ADMIN_ERROR;
            }
        }
    } else {
        logger_log(DEBUG, "admin error en negot write\n\nError. errno message: %s\n\n", strerror(errno));
        
        ret = ADMIN_ERROR;
    }

    return ret;
}

void admin_negot_write_close(const unsigned state, struct selector_key *key) {
    /* Do nothing */
}
