#ifndef ADMIN_H_
#define ADMIN_H_

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#include "commands.h"

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

/* Admin parser states */
typedef enum admin_parser_state {
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

    admin_done_p,
    admin_error,

} admin_parser_state;


/* Admin parser struct */
typedef struct admin_parser {

    enum admin_parser_state state;
    enum admin_errors error;

    struct admin_received_data * data;

} admin_parser;

/** Initializes the admin parser */
void
admin_parser_init(struct admin_parser * p);

/** Only resets state, error and data option*/
void
admin_parser_reset(struct admin_parser * p);

/**
 * For each buffer element calls admin_parser_feed until empty,  
 * completed parsing or more bytes required.
 * 
 * @param errored output param. If != NULL that value is not modified.
 */
enum admin_parser_state
admin_consume(buffer * b, struct admin_parser * p, bool * errored);

/** Delivers a byte to the parser, when finish returns current state */
enum admin_parser_state
admin_parser_feed(struct admin_parser * p, uint8_t byte);

/** If got to a state of error, gets error representation */
const char *
admin_error_description(const struct admin_parser * p);

/**
 * Allows to know to the admin_parser_feed if should keep sending bytes or not.
 * If finished fills errored whith true or false depending if error or not.
 */
bool
admin_is_done(const enum admin_parser_state state, bool * errored);

/** Frees resources used by the parser */
void
admin_parser_close(struct admin_parser * p);

/** Writes on buffer */
int16_t 
admin_marshall(buffer *b, struct admin_data_word data);

#endif