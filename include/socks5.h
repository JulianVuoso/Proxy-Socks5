#ifndef SOCKS5_H_14a057e93d76b8145a82a22572d1f1983775644c
#define SOCKS5_H_14a057e93d76b8145a82a22572d1f1983775644c

#include <stdint.h>
#include "selector.h"

#define MAX_CONCURRENT_CON  600

/* Recibe la llave del item */
void socks5_passive_accept(selector_key * key);
/* Destruye toda la pool de socks */
/* void socks5_pool_destroy(void); */

unsigned get_concurrent_conn();
uint64_t get_historical_conn();
uint64_t get_buffer_read_size();
uint64_t get_buffer_write_size();
void set_buffer_read_size(uint64_t size);
void set_buffer_write_size(uint64_t size);

#endif