#ifndef COMMANDS_H_
#define COMMANDS_H_

#include <stdint.h>
#include "users.h"

#define STATUS_INDEX            1

typedef struct admin_data_word {
    uint8_t * value;
    uint64_t index;
    uint64_t length;
} admin_data_word;

/* Possible commands */
enum commands {
    command_add_user = 0x00,
    command_del_user = 0x01,
    command_list_user = 0x02,
    command_get_metric = 0x03,
    command_get_config = 0x04,
    command_set_config = 0x05,

    command_none = 0xFF,
};

/* Possible metrics */
enum metric_options {
    metric_hist_conn = 0x00,
    metric_conc_conn = 0x01,
    metric_hist_btransf = 0x02,

    metric_none = 0xFF,
};

/* Possible configurations */
enum config_options {
    config_buff_read_size = 0x00,
    config_buff_write_size = 0x01,
    config_gen_tout = 0x02,
    config_con_tout = 0x03,

    config_none = 0xFF,
};

/* Admin parser errors */
enum admin_errors { 
    admin_error_none = 0x00,
    admin_error_inv_command = 0x01,
    /* users */
    admin_error_inv_ulen = 0x02,
    admin_error_inv_plen = 0x03,
    admin_error_inv_utype = 0x04,

    admin_error_inv_metric = 0x05,
    admin_error_inv_config = 0x06,
    
    admin_error_max_ucount = 0xA0,
    admin_error_inv_value = 0xA1,

    admin_error_server_fail = 0xFF,
};


/* Maps the data received  */
typedef struct admin_received_data {
    /* The selected command */
    enum commands command;
    
    /* Value for  metrics, config or user type option, casted later */
    uint8_t option;

    /* Value for user handling */
    struct admin_data_word * value1;
    struct admin_data_word * value2;
} admin_received_data;

uint8_t
exec_cmd_and_answ(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans);

uint8_t
set_user(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans);

uint8_t
del_user(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans);

uint8_t
get_users(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans);

uint8_t
get_metric(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans);

uint8_t
get_config(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans);

uint8_t
set_config(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans);

#endif