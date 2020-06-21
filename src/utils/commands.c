#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "commands.h"
#include "users.h"
#include "socks5.h" // For metrics and buffer sizes
#include "sm_copy_state.h" // For metric
#include "config.h" // For buffers max and min

#define DATA_BLOCK      3
#define VAL_SIZE_MAX    sizeof(uint64_t)
#define MSG_MAX_LEN     0xFF

#define CMD_STAT_HLEN           2
#define CMD_STAT_VLEN_HLEN      3
#define CMD_STAT_OPT_HLEN       3
#define CMD_STAT_OPT_VLEN_HLEN  4


static uint8_t 
ulong_to_byte_array(uint64_t value, struct admin_data_word * ans);
static uint64_t
byte_array_to_ulong(uint8_t * data, uint8_t length);
static uint8_t
string_to_byte_array(const char * s, uint8_t slen, struct admin_data_word * ans);
static uint8_t
add_inv_value_mssg(const char * type, uint64_t min, uint64_t max, struct admin_data_word * ans);
static uint8_t
set_ans_head(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans, uint8_t hlen);


uint8_t
exec_cmd_and_answ(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans) {
    switch (data->command) {
        case command_add_user: return set_user(error, data, ans);
        case command_del_user: return del_user(error, data, ans);
        case command_list_user: return get_users(error, data, ans);
        case command_get_metric: return get_metric(error, data, ans);
        case command_get_config: return get_config(error, data, ans);
        case command_set_config: return set_config(error, data, ans);
        default: return set_ans_head(error, data, ans, CMD_STAT_HLEN);
    }
}


uint8_t
set_user(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans) {
    if (error != admin_error_none && add_user_to_list(data->value1->value, data->value2->value, data->option) != file_no_error) 
        error = admin_error_server_fail;
    
    return set_ans_head(error, data, ans, CMD_STAT_HLEN);
}

uint8_t
del_user(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans) {
    delete_user_from_list(data->value1->value);

    return set_ans_head(error, data, ans, CMD_STAT_HLEN);
}

uint8_t
get_users(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans) {
    if (!set_ans_head(error, data, ans, CMD_STAT_VLEN_HLEN)) return 0;
    if (error != admin_error_none) return 1;
    
    ans->index--; // If there is no error, override vlen = 0

    // todo get users

    return 1;
}

uint8_t
get_metric(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans) {
    if (!set_ans_head(error, data, ans, CMD_STAT_OPT_VLEN_HLEN)) return 0;
    if (error != admin_error_none) return 1;

    ans->index--; // If there is no error, override vlen = 0
    switch (data->option) {
        case metric_hist_conn: return ulong_to_byte_array(get_historical_conn(), ans);
        case metric_conc_conn: return ulong_to_byte_array(get_concurrent_conn(), ans);
        case metric_hist_btransf: return ulong_to_byte_array(get_transf_bytes(), ans);
        default: return 0; // Should never reach here
    }
}

uint8_t
get_config(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans) {
    if (!set_ans_head(error, data, ans, CMD_STAT_OPT_VLEN_HLEN)) return 0;
    if (error != admin_error_none) return 1;
    
    ans->index--; // If there is no error, override vlen = 0
    switch (data->option) {
        case config_buff_read_size: return ulong_to_byte_array(get_buffer_read_size(), ans);
        case config_buff_write_size: return ulong_to_byte_array(get_buffer_write_size(), ans);
        case config_sel_tout: // return ulong_to_byte_array(get_timeout(), ans); TODO implement
        default: return 0; // Should never reach here
    }
}

uint8_t
set_config(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans) {
    if (!set_ans_head(error, data, ans, CMD_STAT_OPT_HLEN)) return 0;
    
    if (data->value1->length > VAL_SIZE_MAX)
        return string_to_byte_array("value exceedes possible representation limit", 0, ans);

    uint64_t value = byte_array_to_ulong(data->value1->value, data->value1->length);
    switch (data->option) {
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
            if (value > MAX_BUF_SIZE || value < MIN_BUF_SIZE)
                return add_inv_value_mssg("Timeout", MIN_TIMEOUT, MAX_TIMEOUT, ans);
            // TODO set here value when ready
            break;
        default: return 0; // Should never reach here
    }
    return 1;
}



/** Auxiliary functions */

static uint8_t 
ulong_to_byte_array(uint64_t value, struct admin_data_word * ans) {
    ans->value = realloc(ans->value, ans->index + VAL_SIZE_MAX + 1);
    if (ans->value == NULL) return 0;
    
    bool zeros = true;
    uint8_t aux, len = 0;
    for (uint8_t i = VAL_SIZE_MAX * 8; i != 0; i -= 8 ) {
        aux = value >> i;
        if (zeros) {
            if (aux != 0) {
                zeros = 0;
                ans->value[ans->index + 1 + len++] = aux;
            }
        } else ans->value[ans->index + 1 + len++] = aux;
    }
    ans->value[ans->index] = len; // Sets value length
    ans->index += len;
    ans->length = ans->index;
    ans->value = realloc(ans->value, ans->length);
    if (ans->value == NULL) return 0; // Should not, but just in case
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
string_to_byte_array(const char * s, uint8_t slen, struct admin_data_word * ans) {
    if (!slen) slen = strlen(s);
    ans->length = ans->index + 1 + slen;
    ans->value = realloc(ans->value, ans->length);
    if (ans->value == NULL) return 0;

    ans->value[ans->index++] = slen;
    while (*s != '\0')
        ans->value[ans->index++] = *(s++);
    return 1;
}

static uint8_t
add_inv_value_mssg(const char * type, uint64_t min, uint64_t max, struct admin_data_word * ans) {
    char s[MSG_MAX_LEN + 1];
    int16_t slen = printf(s, MSG_MAX_LEN + 1, "%s value must be between %ld AND %ld", type, min, max);
    if (slen < -1) return 0;
    return string_to_byte_array(s, (uint8_t) slen, ans); 
}

static uint8_t
set_ans_head(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans, uint8_t hlen) {
    ans->index = 0;
    ans->length = hlen;
    ans->value = realloc(ans->value, ans->length);
    if (ans->value == NULL) return 0;

    ans->value[ans->index++] = data->command;
    ans->value[ans->index++] = error;  
    if (hlen > 2) ans->value[ans->index++] = data->option;
    if (hlen > 3) ans->value[ans->index++] = 0;
    return 1;
}