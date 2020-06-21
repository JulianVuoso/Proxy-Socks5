#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/sctp.h>
#include <errno.h>

#include "commands.h"
#include "adminmt.h"
#include "admin.h"
#include "logger.h"

void admin_cmd_init(const unsigned state, struct selector_key *key) {
    struct admin_cmd_st * st = &ADMIN_ATTACH(key)->client.cmd;
    st->read_buf = &(ADMIN_ATTACH(key)->read_buffer);
    st->write_buf = &(ADMIN_ATTACH(key)->write_buffer);
    st->reply_word.value = NULL;
    st->marshall_error = false;
    admin_parser_init(&st->parser);
}

void admin_cmd_close(const unsigned state, struct selector_key *key) {
    struct admin_cmd_st * st = &ADMIN_ATTACH(key)->client.cmd;
    if (st->reply_word.value != NULL) free(st->reply_word.value);
    admin_parser_close(&st->parser);
}


unsigned admin_cmd_process(struct selector_key *key) {
    struct admin_cmd_st * st_vars = &ADMIN_ATTACH(key)->client.cmd;

    if (!exec_cmd_and_answ(st_vars->parser.error, st_vars->parser.data, &st_vars->reply_word))
        return ADMIN_ERROR; 
    if (admin_marshall(st_vars->write_buf, st_vars->reply_word) < 0)
        st_vars->marshall_error = true;

    return ADMIN_CMD;
}

unsigned admin_cmd_read(struct selector_key *key) {
    struct admin_cmd_st * st_vars = &ADMIN_ATTACH(key)->client.cmd;
    unsigned ret = ADMIN_CMD;
    bool errored = false;
    size_t nbytes;
    uint8_t * buf_write_ptr = buffer_write_ptr(st_vars->read_buf, &nbytes);
    ssize_t n = sctp_recvmsg(key->fd, buf_write_ptr, nbytes, NULL, NULL, NULL, NULL);

    if (n > 0) {
        buffer_write_adv(st_vars->read_buf, n);
        do {
            const enum admin_state state = admin_consume(st_vars->read_buf, &st_vars->parser, &errored);
            if (admin_is_done(state, 0)) {
                if (selector_add_interest(key->s, key->fd, OP_WRITE) == SELECTOR_SUCCESS) {
                    ret = admin_cmd_process(key);
                    admin_parser_reset(&st_vars->parser);
                    if (st_vars->marshall_error) {
                        if (selector_remove_interest(key->s, key->fd, OP_READ) != SELECTOR_SUCCESS) // If marshall cant 
                            ret = ADMIN_ERROR;
                        break;
                    }
                } else {
                    ret = ADMIN_ERROR;
                    break;
                }
            }
        } while (buffer_can_read(st_vars->read_buf));
    } else ret = ADMIN_ERROR;

    return ret;
}

unsigned admin_cmd_write(struct selector_key *key) {
    struct admin_cmd_st * st_vars = &ADMIN_ATTACH(key)->client.cmd;
    unsigned ret = ADMIN_CMD;
    size_t nbytes;
    uint8_t * buf_read_ptr = buffer_read_ptr(st_vars->write_buf, &nbytes);
    ssize_t n = sctp_sendmsg(key->fd, buf_read_ptr, nbytes, NULL, 0, 0, 0, 0, 0, 0);

    printf("Hello the n is %ld\n", n);

    if (n > 0) {
        buffer_read_adv(st_vars->write_buf, n);
        if (!buffer_can_read(st_vars->write_buf)) { // Finish sending message
            if (selector_remove_interest(key->s, key->fd, OP_WRITE) == SELECTOR_SUCCESS) 
                ret = ADMIN_CMD;
            else ret = ADMIN_ERROR;
            if (st_vars->marshall_error) {
                logger_log(DEBUG, "admin error full buffer on command write\n\n");
                ret = ADMIN_ERROR; // This might change
            }  
        }
    } else {
        logger_log(DEBUG, "admin error on command write\n\nError. errno message: %s\n\n", strerror(errno));
        ret = ADMIN_ERROR;
    }
    return ret;
}