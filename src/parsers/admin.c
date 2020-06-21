#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "admin.h"

#define UNAME   0
#define PASS    1
#define VALUE   2


static void 
admin_data_word_init(admin_parser * p, uint8_t type, uint8_t length);
static bool
admin_data_word_add(admin_parser * p, uint8_t type, uint8_t byte);
static int16_t
admin_marshall_send_head(buffer * b, uint8_t length, uint8_t * data);
static int16_t
admin_marshall_send(buffer * b, uint8_t hlen, uint8_t * head, uint8_t dlen, uint8_t * data);




void
admin_parser_init(admin_parser * p) {
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
admin_parser_reset(admin_parser * p) {
    p->state = admin_command;
    p->error = admin_error_none;
    p->data->option = 0;
    p->data->command = admin_command_none;
}

admin_state
admin_consume(buffer * b, admin_parser * p, bool * errored) {
    admin_state state = p->state;
    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        state = admin_parser_feed(p, c);
        if (admin_is_done(state, errored))
            break;
    }
    return state;
}

admin_state
admin_parser_feed(admin_parser * p, uint8_t byte) {
    switch (p->state) {
        case admin_command:
        /* Checks the commnad received */
            p->data->command = byte;
            switch (byte) {
                case admin_command_add_user: p->state = admin_utype; break;
                case admin_command_del_user: p->state = admin_get_ulen; break;
                case admin_command_list_user: p->state = admin_done; break;
                case admin_command_get_metric: p->state = admin_metric; break;
                case admin_command_get_config:
                case admin_command_set_config: p->state = admin_config; break;
                default: 
                    p->state = admin_error;
                    p->error = admin_error_inv_command;
                    break;
            }
            break;

        case admin_get_ulen:
        /* Gets the user length, can't be 0 (except for user delete) */
            if (byte == 0) {
                if (p->data->command == admin_command_del_user) {
                    p->state = admin_done;
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
                if (p->data->command == admin_command_del_user) 
                    p->state = admin_done;
                else p->state = admin_get_plen;
            } 
            break;

        case admin_get_plen:
        /* Gets password length */
            p->state = admin_get_pass;
            admin_data_word_init(p, PASS, byte);
            break;

        case admin_get_pass:
        /* Gets password */
            if (admin_data_word_add(p, PASS, byte)) 
                p->state = admin_done; 
            break;

        case admin_utype:
        /* For user types */
            p->data->option = byte;
            switch (byte) {
                case admin_user_type_client:
                case admin_user_type_admin: p->state = admin_get_ulen; break;
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
                case admin_metric_hist_conn:
                case admin_metric_conc_conn:
                case admin_metric_hist_btransf: p->state = admin_done; break;
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
                case admin_config_buff_both_size:
                case admin_config_buff_read_size:
                case admin_config_buff_write_size:
                case admin_config_sel_tout:
                    if (p->data->command == admin_command_get_config)
                        p->state = admin_done;
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
                p->state = admin_done; 
            break;

        default:
            fprintf(stderr, "unknown state %d\n", p->state);
            abort();
    }
    return p->state;
}

const char *
admin_error_description(const admin_parser * p) {
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
        case admin_error_inv_vlen:
            ret = "value length is too big";
            break;
        default:
            ret = "";
            break;
    }
    return ret;
}

bool
admin_is_done(const admin_state state, bool * errored) {
    bool ret;
    switch (state) {
        case admin_error:
            if (errored != NULL)  *errored = true;
            ret = true;
            break;
        case admin_done:
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
admin_parser_close(admin_parser * p) {
    if (p == NULL) return;
    if (p->data->value1->value != NULL) free(p->data->value1->value);
    free(p->data->value1);
    if (p->data->value2->value != NULL) free(p->data->value2->value);
    free(p->data->value2);
    free(p->data);
}





int16_t
admin_marshall(buffer *b, const admin_parser * p) {
    uint8_t header[4];
    header[0] = p->data->command;
    header[1] = p->error;
    header[2] = p->data->option;
    header[3] = 0;

    switch (p->data->command) {
        case admin_command_list_user: 
            if (p->error != admin_error_none) // If error sends -> CMD STAT NULEN = 0
                return admin_marshall_send_head(b, 3, header); // header[2] = 0, default not modified
            // If ok sends -> CMD STAT + DATA(NULEN NUSERS ....)
            return admin_marshall_send(b, 2, header, p->data->value2->length, p->data->value2->value);
        case admin_command_get_metric: 
        case admin_command_get_config:  
            if (p->error != admin_error_none) // If error sends -> CMD STAT CONFIG/METRIC VLEN = 0
                return admin_marshall_send_head(b, 4, header);
            // If ok sends -> CMD STAT CONFIG/METRIC + DATA
            return admin_marshall_send(b, 3, header, p->data->value2->length, p->data->value2->value);
        case admin_command_set_config:
            // Always sends -> CMD STAT CONFIG + DATA(MLEN MESSG)
            return admin_marshall_send(b, 3, header, p->data->value2->length, p->data->value2->value);
        case admin_command_add_user: 
        case admin_command_del_user: 
        default: 
            return admin_marshall_send_head(b, 2, header);
    }
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

static int16_t
admin_marshall_send_head(buffer * b, uint8_t length, uint8_t * data) {
    return admin_marshall_send(b, length, data, 0, NULL);
}

static int16_t
admin_marshall_send(buffer * b, uint8_t hlen, uint8_t * head, uint8_t dlen, uint8_t * data) {
    uint64_t n;
    uint8_t * buff = buffer_write_ptr(b, &n);
    if (n < hlen + dlen) return -1;
    for (uint32_t i = 0; i < hlen; i++) buff[i] = head[i];
    for (uint32_t i = 0; i < dlen; i++) buff[i] = data[i];
    return hlen + dlen;
}





/** Functions for state machine */

admin_errors
admin_execute_command(admin_received_data * data, admin_errors error) {
    if (error != admin_error_none) return error;
    switch (data->command) {    // All ret 0x00 if succes or 0xFF if srver error.
                                // Except set config, can return 0x06 inv value with message.
                                // To those who need we shall pass the word value2 to be written the response data.
        case admin_command_add_user: return (admin_errors) 0x00; // TODO add user.
        case admin_command_del_user: return (admin_errors) 0x00;  // TODO delete user.
        case admin_command_list_user: return (admin_errors) 0x00; // TODO list users.
        case admin_command_get_metric: return (admin_errors) 0x00;  // TODO get metrics.
        case admin_command_get_config: return (admin_errors) 0x00; // TODO get config.
        case admin_command_set_config: return (admin_errors) 0x00; // TOD set config. 
        default: 
            fprintf(stderr, "unknown command %d\n", data->command);
            abort();
    }
}

static uint64_t
admin_data_value_convert(admin_parser * p) {
    admin_data_word * value = p->data->value1;
    uint64_t ret = 0;
    for (uint8_t i = 0; i < value->length; i++) {
        ret = (ret << 8) + value->value[i];
    }
    return ret;
}