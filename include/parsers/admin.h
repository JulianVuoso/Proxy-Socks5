#ifndef ADMIN_H_
#define ADMIN_H_

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

/**
 * ******************** Add User ********************
	+-----+------+----------+------+------------+-------+
	| CMD | ULEN |   UNAME  | PLEN |   PASSWD   | UTYPE |
	+-----+------+----------+------+------------+-------+
	|  1  |  1   | 1 to 255 |   1  |  1 to 255  |   1   |
	+-----+------+----------+------+------------+-------+

	Where:
		- CMD		X'01'
		- ULEN		-> length of the UNAME field
		- UNAME 	-> username
		- PLEN		-> length of the PASSWD field that follows
		- PASSWD	-> password associated with the given UNAME
		- UTYPE		-> user type
			~ CLIENT	X'00'
			~ ADMIN		X'01'

 * ******************** Delete User ********************
    +-----+------+----------+
    | CMD | ULEN |   UNAME  |
    +-----+------+----------+
    |  1  |  1   | 1 to 255 |
    +-----+------+----------+

	Where:
		- CMD		X'02'
		- ULEN		-> length of the UNAME field
		- UNAME 	-> username to remove

* ******************** List Usernames ********************
    +-----+
    | CMD |
    +-----+
    |  1  |
    +-----+
	
	Where:
		- CMD		X'03'

* ******************** Get Metrics ********************
    +-----+--------+
    | CMD | METRIC |
    +-----+--------+
    |  1  |   1    |
    +-----+--------+
	
	Where:
		- CMD		X'04'
		- METRIC 	-> requested metric
			~ HISTORIC CONNECTIONS		X'00'
			~ CONCURRENT CONNECTIONS	X'01'
			~ HISTORIC BYTES TRANSF		X'02'

* ******************** Get Configurations ********************
    +-----+--------+
    | CMD | CONFIG |
    +-----+--------+
    |  1  |   1    |
    +-----+--------+
	
	Where:
		- CMD		X'05'
		- CONFIG 	-> requested config
			~ BUFFER SIZE BOTH  X'00'		
			~ BUFFER READ		X'01'
			~ BUFFER WRITE		X'02'
			~ SELECT TIMEOUT	X'03'
	
 * ******************** Change Configurations ********************  
    +-----+--------+------+----------+
    | CMD | CONFIG | VLEN |   VALUE  |
    +-----+--------+------+----------+
    |  1  |   1    |  1   | 0 to 255 |
    +-----+--------+------+----------+
	
	Where:
		- CMD		X'06'
		- CONFIG 	-> requested config
			~ BUFFER SIZE BOTH  X'00'		
			~ BUFFER READ		X'01'
			~ BUFFER WRITE		X'02'
			~ SELECT TIMEOUT	X'03'
		- VLEN		-> length of the VALUE filed
		- VALUE 	-> value of the requested config

*/

/* Possible commands */
typedef enum admin_commands {
    admin_command_add_user = 0x01,
    admin_command_del_user = 0x02,
    admin_command_list_user = 0x03,
    admin_command_get_metric = 0x04,
    admin_command_get_config = 0x05,
    admin_command_set_config = 0x06,

    admin_command_none = 0xFF,
} admin_commands;

/* Possible user typed */
typedef enum admin_user_types {
    admin_user_type_client = 0x00,
    admin_user_type_admin = 0x01,

    admin_user_type_none = 0xFF,
} admin_user_types;

/* Possible metrics */
typedef enum admin_metrics {
    admin_metric_hist_conn = 0x00,
    admin_metric_conc_conn = 0x01,
    admin_metric_hist_btransf = 0x02,

    admin_metric_none = 0xFF,
} admin_metrics;

/* Possible configurations */
typedef enum admin_configs {
    admin_config_buff_both_size = 0x00,
    admin_config_buff_read_size = 0x01,
    admin_config_buff_write_size = 0x03,
    admin_config_sel_tout = 0x04,

    admin_config_none = 0xFF,
} admin_configs;

/* Admin parser states */
typedef enum admin_state {
    admin_command,
    admin_config,
    admin_metric,
    admin_utype,

    admin_get_ulen,
    admin_get_user,
    admin_get_plen,
    admin_get_pass,    
    admin_get_vlen,
    admin_get_value,

    admin_done,
    admin_error,

} admin_state;

/* Admin parser errors */
typedef enum admin_errors { // TODO no son todos estos
    admin_error_inv_command = 0x01,
    admin_error_inv_ulen = 0x02,
    admin_error_inv_utype = 0x03,
    admin_error_inv_metric = 0x04,
    admin_error_inv_config = 0x05,
    admin_error_inv_value = 0x06,
    admin_error_inv_vlen = 0x07, // TODO se agrega en protocol.txt

    admin_error_server_fail = 0xFF,
    admin_error_none = 0x00,
} admin_errors;

typedef struct admin_data_word {
    uint8_t * value;
    uint8_t index;
    uint8_t length;
} admin_data_word;

/* Maps the data received  */
typedef struct admin_received_data {
    /* The selected command */
    admin_commands command;
    
    /* Value for  metrics, config or user type option, casted later */
    uint8_t option;

    /* Value for user handling */
    admin_data_word * value1;
    admin_data_word * value2;
} admin_received_data;

/* Admin parser struct */
typedef struct admin_parser {

    admin_state state;
    admin_errors error;

    admin_received_data * data;

} admin_parser;

/** Initializes the admin parser */
void
admin_parser_init(admin_parser * p);

/**
 * For each buffer element calls admin_parser_feed until empty,  
 * completed parsing or more bytes required.
 * 
 * @param errored output param. If != NULL that value is not modified.
 */
admin_state
admin_consume(buffer * b, admin_parser * p, bool * errored);

/** Delivers a byte to the parser, when finish returns current state */
admin_state
admin_parser_feed(admin_parser * p, uint8_t byte);

/** If got to a state of error, gets error representation */
const char *
admin_error_description(const admin_parser * p);

/**
 * Allows to know to the admin_parser_feed if should keep sending bytes or not.
 * If finished fills errored whith true or false depending if error or not.
 */
bool
admin_is_done(const admin_state state, bool * errored);

/** Frees resources used by the parser */
void
admin_parser_close(admin_parser * p);

/** Executes the corresponding command */
admin_errors
admin_execute_command(admin_received_data * data);

/** Writes on buffer */
int16_t 
admin_marshall(buffer *b, const admin_parser * p);

#endif