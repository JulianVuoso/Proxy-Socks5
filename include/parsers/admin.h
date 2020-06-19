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


#endif