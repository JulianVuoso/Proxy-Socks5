#ifndef COMMANDS_H_
#define COMMANDS_H_

#include <stdint.h>
#include "users.h"

typedef struct admin_data_word {
    uint8_t * value;
    uint8_t index;
    uint8_t length;
} admin_data_word;


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

/* Possible commands */
enum commands {
    command_add_user = 0x01,
    command_del_user = 0x02,
    command_list_user = 0x03,
    command_get_metric = 0x04,
    command_get_config = 0x05,
    command_set_config = 0x06,

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
    config_buff_both_size = 0x00,
    config_buff_read_size = 0x01,
    config_buff_write_size = 0x02,
    config_sel_tout = 0x03,

    config_none = 0xFF,
};

/* Admin parser errors */
enum admin_errors { 
    admin_error_inv_command = 0x01,
    admin_error_inv_ulen = 0x02,
    admin_error_inv_utype = 0x03,
    admin_error_inv_metric = 0x04,
    admin_error_inv_config = 0x05,
    admin_error_inv_value = 0x06,

    admin_error_server_fail = 0xFF,
    admin_error_none = 0x00,
};

uint8_t
exec_cmd_and_answ(enum admin_errors error, struct admin_received_data * data, struct admin_data_word * ans);

enum admin_errors
set_user(enum user_level level, uint8_t * name, uint8_t * pass);

enum admin_errors
del_user(uint8_t * username);

enum admin_errors
get_users(struct admin_data_word * ans);

enum admin_errors
get_metric(enum metric_options metric, struct admin_data_word * ans);

enum admin_errors
get_config(enum config_options config, struct admin_data_word * ans);

enum admin_errors
set_config(enum config_options config, uint8_t * value, uint8_t vlen,struct admin_data_word * msg);

#endif