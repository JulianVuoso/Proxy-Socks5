#include <string.h>
#include <stdio.h>

#include "commands.h"
#include "users.h"
#include "socks5.h" // For metrics and buffer sizes
#include "sm_copy_state.h" // For metric
#include "config.h" // For buffers max and min

#define DATA_BLOCK      3
#define VAL_SIZE_MAX    sizeof(uint64_t)


static uint8_t 
ulong_to_byte_array(uint64_t value, struct admin_data_word * ans);
static uint64_t
byte_array_to_ulong(uint8_t * data, uint8_t length);
static uint8_t
copy_string_to_data(const char * s, struct admin_data_word * ans);
static enum admin_errors
add_inv_value_mssg(const char * type, uint64_t min, uint64_t max, struct admin_data_word * ans);


uint8_t
exec_cmd_and_answ(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans) {
    
    if (error == admin_error_none) 
        switch (data->command) {
            case command_add_user: 
                error = set_user(data->option, data->value1->value, data->value2->value); break;
            case command_del_user: 
                error = del_user(data->value1->value); break;
            case command_list_user: 
                error = get_users(); break;
            case command_get_metric: 
                error = get_metric(data->option); break;
            case command_get_config:  
                error = get_config(data->option); break;
            case command_set_config:
                error = set_config(data->option); break;
            default:
        }


    // uint8_t header[4];
    // header[0] = data->command;
    // header[1] = error;
    // header[2] = data->option;
    // header[3] = 0;
    // switch (data->command) {
    //     case command_list_user: 
    //         if (error != admin_error_none) // If error sends -> CMD STAT NULEN = 0
    //             return admin_marshall_send_head(b, 3, header); // header[2] = 0, default not modified
    //         // If ok sends -> CMD STAT + DATA(NULEN NUSERS ....)
    //         return admin_marshall_send(b, 2, header, p->data->value2->length, p->data->value2->value);
    //     case command_get_metric: 
    //     case command_get_config:  
    //         if (error != admin_error_none) // If error sends -> CMD STAT CONFIG/METRIC VLEN = 0
    //             return admin_marshall_send_head(b, 4, header);
    //         // If ok sends -> CMD STAT CONFIG/METRIC + DATA
    //         return admin_marshall_send(b, 3, header, p->data->value2->length, p->data->value2->value);
    //     case command_set_config:
    //         // Always sends -> CMD STAT CONFIG + DATA(MLEN MESSG)
    //         return admin_marshall_send(b, 3, header, p->data->value2->length, p->data->value2->value);
    //     case command_add_user: 
            
    //     case command_del_user: 
    //     default: 
    //         return admin_marshall_send_head(b, 2, header);
    // }





// enum admin_errors
// admin_execute_command(admin_received_data * data, enum admin_errors error) {
//     if (error != admin_error_none) return error;
//     switch (data->command) {    // All ret 0x00 if succes or 0xFF if srver error.
//                                 // Except set config, can return 0x06 inv value with message.
//                                 // To those who need we shall pass the word value2 to be written the response data.
//         case command_add_user: return (enum admin_errors) 0x00; // TODO add user.
//         case command_del_user: return (enum admin_errors) 0x00;  // TODO delete user.
//         case command_list_user: return (enum admin_errors) 0x00; // TODO list users.
//         case command_get_metric: return (enum admin_errors) 0x00;  // TODO get metrics.
//         case command_get_config: return (enum admin_errors) 0x00; // TODO get config.
//         case command_set_config: return (enum admin_errors) 0x00; // TOD set config. 
//         default: 
//             fprintf(stderr, "unknown command %d\n", data->command);
//             abort();
//     }
// }
}


enum admin_errors
set_user(enum user_level level, uint8_t * name, uint8_t * pass) {
    if (add_user_to_list(name, pass, level) != file_no_error) return admin_error_server_fail;
    return admin_error_none;
}

enum admin_errors
del_user(uint8_t * name) {
    delete_user_from_list(name);
    return admin_error_none;
}

enum admin_errors
get_users(struct admin_data_word * ans) {

    return admin_error_none;
}

enum admin_errors
get_metric(enum metric_options metric, struct admin_data_word * ans) {
    switch (metric) {
    case metric_hist_conn:
        if (!ulong_to_byte_array(get_historical_conn(), ans))
            return admin_error_server_fail;
        break;
    case metric_conc_conn:
        if (!ulong_to_byte_array(get_concurrent_conn(), ans))
            return admin_error_server_fail;
        break;
    case metric_hist_btransf:
        if (!ulong_to_byte_array(get_transf_bytes(), ans))
            return admin_error_server_fail;
        break;
    default:
        return admin_error_server_fail; // Should never reach here
    }
    return admin_error_none;
}

enum admin_errors
get_config(enum config_options config, struct admin_data_word * ans) {
    switch (config) {
        case config_buff_both_size: // TODO the hell do I do here?
            break;
        case config_buff_read_size:
            if (!ulong_to_byte_array(get_buffer_read_size(), ans))
                return admin_error_server_fail;
        case config_buff_write_size:
            if (!ulong_to_byte_array(get_buffer_write_size(), ans))
                return admin_error_server_fail;
        case config_sel_tout: // TODO implement
            // if (!ulong_to_byte_array(get_timeout(), ans))
                // return admin_error_server_fail;
        default:
            return admin_error_server_fail; // Should never reach here
    }
    return admin_error_none;
}

enum admin_errors
set_config(enum config_options config, uint8_t * value, uint8_t vlen, struct admin_data_word * ans) {
    if (vlen > VAL_SIZE_MAX) {
        if (!copy_string_to_data("value exceedes possible representation limit", ans)) 
            return admin_error_server_fail;
        return admin_error_inv_value;
    }

    uint64_t value = byte_array_to_ulong(value, vlen);
    char * aux_s;
    switch (config) {
        case config_buff_both_size:
            if (value > MAX_BUF_SIZE || value < MIN_BUF_SIZE) 
                return add_inv_value_mssg("Buffer", MIN_BUF_SIZE, MAX_BUF_SIZE, ans);
            set_buffer_read_size(value);
            set_buffer_write_size(value);
            break;
        case config_buff_read_size:
            if (value > MAX_BUF_SIZE || value < MIN_BUF_SIZE) 
                return add_inv_value_mssg("Buffer", MIN_BUF_SIZE, MAX_BUF_SIZE, ans);
            set_buffer_read_size(value);
            break;
        case config_buff_write_size:
            if (value > MAX_BUF_SIZE || value < MIN_BUF_SIZE) 
                return add_inv_value_mssg("Buffer", MIN_BUF_SIZE, MAX_BUF_SIZE, ans);
            set_buffer_write_size(value);
            break;
        case config_sel_tout:
            if (value > MAX_BUF_SIZE || value < MIN_BUF_SIZE) {
                return add_inv_value_mssg("Timeout", MIN_TIMEOUT, MAX_TIMEOUT, ans);
            // TODO set here value when ready
            break;
        default:
            return admin_error_server_fail; // Should never reach here
    }
    return admin_error_none;
}



/** Auxiliary functions */

static uint8_t 
ulong_to_byte_array(uint64_t value, struct admin_data_word * ans) {
    *dlen = 1;
    *data = realloc(*data, VAL_SIZE_MAX + 1);
    if (*data == NULL) return 0;

    bool zeros = true;
    uint8_t aux;
    for (uint8_t i = VAL_SIZE_MAX * 8; i != 0; i -= 8 ) {
        aux = value >> i;
        if (zeros) {
            if (aux != 0) {
                zeros = 0;
                *data[*dlen++] = aux;
            }
        } else *data[*dlen++] = aux;
    }
    *data[0] = *dlen - 1; // Sets value length
    *data = realloc(*data, *dlen);
    if (*data == NULL) return 0; // Should not, but just in case
    return 1;
}

static uint64_t
byte_array_to_ulong(uint8_t * data, uint8_t length) {
    uint64_t ret = 0;
    for (uint8_t i = 0; i < length; i++) {
        ret = (ret << 8) + data[i];
    }
    return ret;
}

static uint8_t
copy_string_to_data(const char * s, struct admin_data_word * ans) {
    *dlen = strlen(s) + 1;
    *data = realloc(*data, *dlen);
    if (*data == NULL) return 0;

    for (uint8_t i = 0; s[i] != '\0'; i++)
        *data[i + 1] = s[i];

    return 1;
}

static enum admin_errors
add_inv_value_mssg(const char * type, uint64_t min, uint64_t max, struct admin_data_word * ans) {
    char * s;
    sprintf(s, "%s value must be between %dl AND %dl", type, min, max);
    if (!copy_string_to_data(s, data, dlen)) 
        return admin_error_server_fail;
    return admin_error_inv_value;
}