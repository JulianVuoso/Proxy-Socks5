#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "admin.h"
#include "commands.h"

#define UNAME   0
#define PASS    1
#define VALUE   2


static void 
admin_data_word_init(admin_parser * p, uint8_t type, uint8_t length);
static bool
admin_data_word_add(admin_parser * p, uint8_t type, uint8_t byte);


void
admin_parser_init(struct admin_parser * p) {
    p->data = calloc(1, sizeof(admin_received_data));
    if (p->data == NULL) {
        p->state = admin_error;
        p->state = admin_error_server_fail;
        return;
    }
    admin_parser_reset(p);
    p->data->value1 = calloc(1, sizeof(admin_data_word));
    p->data->value2 = calloc(1, sizeof(admin_data_word));
    if (p->data->value1 == NULL || p->data->value2 == NULL) {
        p->state = admin_error;
        p->state = admin_error_server_fail;
        return;
    }
}

void
admin_parser_reset(struct admin_parser * p) {
    p->state = admin_command;
    p->error = admin_error_none;
    p->data->option = 0;
    p->data->command = command_none;
}

enum admin_parser_state
admin_consume(buffer * b, struct admin_parser * p, bool * errored) {
    admin_parser_state state = p->state;
    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        state = admin_parser_feed(p, c);
        if (admin_is_done(state, errored))
            break;
    }
    return state;
}

enum admin_parser_state
admin_parser_feed(struct admin_parser * p, uint8_t byte) {
    switch (p->state) {
        case admin_command:
        /* Checks the commnad received */
            p->data->command = byte;
            switch (byte) {
                case command_add_user: p->state = admin_utype; break;
                case command_del_user: p->state = admin_get_ulen; break;
                case command_list_user: p->state = admin_done_p; break;
                case command_get_metric: p->state = admin_metric; break;
                case command_get_config:
                case command_set_config: p->state = admin_config; break;
                default: 
                    p->state = admin_error;
                    p->error = admin_error_inv_command;
                    break;
            }
            break;

        case admin_get_ulen:
        /* Gets the user length, can't be 0 (except for user delete) */
            if (byte == 0) {
                if (p->data->command == command_del_user) {
                    p->state = admin_done_p;
                } else {
                   p->state = admin_error;
                    p->error = admin_error_inv_ulen; 
                }
            } else {
                p->state = admin_get_user;
                admin_data_word_init(p, UNAME, byte);
            }
            break;
        
        case admin_get_user:
        /* Gets the user */
            if (admin_data_word_add(p, UNAME, byte)) {
                if (p->data->command == command_del_user) 
                    p->state = admin_done_p;
                else p->state = admin_get_plen;
            } 
            break;

        case admin_get_plen:
        /* Gets password length, cant be 0 */
            if (byte == 0) {
                p->state = admin_error;
                p->error = admin_error_inv_plen;
            } else {
                p->state = admin_get_pass;
                admin_data_word_init(p, PASS, byte);
            }
            break;

        case admin_get_pass:
        /* Gets password */
            if (admin_data_word_add(p, PASS, byte)) 
                p->state = admin_done_p; 
            break;

        case admin_utype:
        /* For user types */
            p->data->option = byte;
            switch (byte) {
                case user_client:
                case user_admin: p->state = admin_get_ulen; break;
                default:
                    p->state = admin_error;
                    p->error = admin_error_inv_utype;
                    break;
            }
            break;
        
        case admin_metric:
        /* For metrics */
            p->data->option = byte;
            switch (byte) {
                case metric_hist_conn:
                case metric_conc_conn:
                case metric_hist_btransf: p->state = admin_done_p; break;
                default:
                    p->state = admin_error;
                    p->error = admin_error_inv_metric;
                    break;
            }
            break;
        
        case admin_config:
        /* For configurations */
            p->data->option = byte;
            switch (byte) {
                case config_buff_read_size:
                case config_buff_write_size:
                case config_gen_tout:
                case config_con_tout:
                    if (p->data->command == command_get_config)
                        p->state = admin_done_p;
                    else p->state = admin_get_vlen;
                    break;
                default:
                    p->state = admin_error;
                    p->error = admin_error_inv_config;
                    break;
            }
            break;
        
        case admin_get_vlen:
        /* Gets the value length */
            p->state = admin_get_value;
            admin_data_word_init(p, VALUE, byte);      
            break;
        

        case admin_get_value:
        /* Saves the value, and checks if it finished */
            if (admin_data_word_add(p, VALUE, byte)) 
                p->state = admin_done_p; 
            break;

        default:
            fprintf(stderr, "unknown state %d\n", p->state);
            abort();
    }
    return p->state;
}

const char *
admin_error_description(const struct admin_parser * p) {
    char *ret;
    switch (p->error) {
        case admin_error_inv_command:
            ret = "invalid command";
            break;
        case admin_error_inv_utype:
            ret = "invalid user type";
            break;
        case admin_error_inv_ulen:
            ret = "invalid user length";
            break;
        case admin_error_inv_plen:
            ret = "invalid password length";
            break;
        case admin_error_inv_metric:
            ret = "invalid matric";
            break;
        case admin_error_inv_config:
            ret = "invalid configuration";
            break;
        case admin_error_inv_value:
            ret = "invalid value";
            break;
        case admin_error_server_fail:
            ret = "generated server failure";
            break;
        default:
            ret = "";
            break;
    }
    return ret;
}

bool
admin_is_done(const enum admin_parser_state state, bool * errored) {
    bool ret;
    switch (state) {
        case admin_error:
            if (errored != NULL)  *errored = true;
            ret = true;
            break;
        case admin_done_p:
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
admin_parser_close(struct admin_parser * p) {
    if (p == NULL) return;
    if (p->data->value1->value != NULL) free(p->data->value1->value);
    free(p->data->value1);
    if (p->data->value2->value != NULL) free(p->data->value2->value);
    free(p->data->value2);
    free(p->data);
}


int16_t
admin_marshall(buffer * b, struct admin_data_word data) {
    uint64_t n;
    uint8_t * buff = buffer_write_ptr(b, &n);
    if (data.length > n) return -1;
    for (uint64_t i = 0; i < data.length; i++)
        buff[i] = data.value[i];
    buffer_write_adv(b, data.length);
    return data.index;
}


/* Auxiliary static functions */

static void 
admin_data_word_init(admin_parser * p, uint8_t type, uint8_t length) {
    admin_data_word * word = p->data->value1;
    if (type == PASS) word = p->data->value2;

    word->length = length;
    word->index = 0;
    word->value = realloc(word->value, length + 1);
    if (word->value == NULL) {
        p->state = admin_error;
        p->error = admin_error_server_fail;
    }
    word->value[length] = '\0';
}

static bool
admin_data_word_add(admin_parser * p, uint8_t type, uint8_t byte) {
    admin_data_word * word = p->data->value1;
    if (type == PASS) word = p->data->value2;

    word->value[word->index++] = byte;
    if (word->index == word->length) {
        word->value[word->index] = '\0';
        return true;
    }
    return false;
}
