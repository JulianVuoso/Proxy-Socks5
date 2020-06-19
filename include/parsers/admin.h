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

    Reply
        +-----+--------+
        | CMD | STATUS |
        +-----+--------+
        |  1  |   1    |
        +-----+--------+

	Where: 
		- CMD		X'01'
		- STATUS	-> answer status
			~ SUCCESS			X'00'
			~ INV UTYPE			X'02'
			~ GEN SERVER FAIL	X'FF'


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

    Reply:
    +-----+--------+
    | CMD | STATUS |
    +-----+--------+
    |  1  |   1    |
    +-----+--------+

	Where: 
		- CMD		X'02'
		- STATUS	-> answer status
			~ SUCCESS			X'00'
			~ GEN SERVER FAIL	X'FF'


* ******************** List Usernames ********************
    +-----+
    | CMD |
    +-----+
    |  1  |
    +-----+
	
	Where:
		- CMD		X'03'

    Reply:
	+-----+--------+--------+------+----------+-------+
	| CMD | STATUS | NUSERS | ULEN |   UNAME  | UTYPE |
	+-----+--------+--------+------+----------+-------+
	|  1  |   1    |   2    |  1   | 1 to 255 |   1   |
	+-----+--------+--------+------+----------+-------+
							[------------|------------]
									NUSERS times

	Where: 
		- CMD		X'03'
		- STATUS	-> answer status
			~ SUCCESS			X'00'
			~ GEN SERVER FAIL	X'FF'
		- NUSERS	-> user quantity in "network octet order"
		- ULEN		-> length of the UNAME field
		- UNAME		-> username
		- UTYPE 	-> user type
			~ CLIENT	X'00'
			~ ADMIN		X'01'


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
	
    Reply:
    +-----+--------+--------+------+----------+
    | CMD | STATUS | METRIC | VLEN |   VALUE  |
    +-----+--------+--------+------+----------+
    |  1  |   1    |   1    |  1   | 0 to 255 |
    +-----+--------+--------+------+----------+

	Where: 
		- CMD		X'04'
		- STATUS	-> status answer
			~ SUCCESS			X'00'
			~ INV METRIC		X'03'
			~ GEN SERVER FAIL	X'FF'
		- METRIC 	-> requested metric
			~ HISTORIC CONNECTIONS		X'00'
			~ CONCURRENT CONNECTIONS	X'01'
			~ HISTORIC BYTES TRANSF		X'02'
		- VLEN 		-> length of the VALUE filed
		- VALUE 	-> value of the requested metric


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
	
    Reply:
    +-----+--------+--------+------+----------+
    | CMD | STATUS | CONFIG | VLEN |   VALUE  |
    +-----+--------+--------+------+----------+
    |  1  |   1    |   1    |  1   | 0 to 255 |
    +-----+--------+--------+------+----------+

	Where: 
		- CMD		X'05'
		- STATUS	-> answer status
        	~ SUCCESS			X'00'
			~ INV CONFIG		X'04'
			~ GEN SERVER FAIL	X'FF'
		- CONFIG 	-> requested config
			~ BUFFER SIZE BOTH  X'00'		
			~ BUFFER READ		X'01'
			~ BUFFER WRITE		X'02'
			~ SELECT TIMEOUT	X'03'
		- VLEN 		-> length of the VALUE filed
		- VALUE 	-> value of the requested config


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

    Reply (for valid configuration):
    +-----+--------+--------+
    | CMD | STATUS | CONFIG |
    +-----+--------+--------+
    |  1  |   1    |   1    |
    +-----+--------+--------+

	Where: 
		- CMD		X'06'
		- STATUS	-> answer status
			~ SUCCESS			X'00'
			~ INV CONFIG		X'04'
			~ INV VALUE 		X'05'
			~ GEN SERVER FAIL	X'FF'
		- CONFIG 	-> requested config
			~ BUFFER SIZE BOTH  X'00'		
			~ BUFFER READ		X'01'
			~ BUFFER WRITE		X'02'
			~ SELECT TIMEOUT	X'03'

    Reply(for invalid command)
    +-----+--------+
    | CMD | STATUS |
    +-----+--------+
    |  1  |   1    |
    +-----+--------+

	Where: 
		- CMD		-> requested command
        - STATUS	-> answer status
			~ INV CMD			X'01'
			~ GEN SERVER FAIL	X'FF'
*/


#endif