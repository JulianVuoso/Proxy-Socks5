#ifndef SOCKS5_H_14a057e93d76b8145a82a22572d1f1983775644c
#define SOCKS5_H_14a057e93d76b8145a82a22572d1f1983775644c

#include "selector.h"

/* Recibe la llave del item */
void socks5_passive_accept(selector_key * key);
/* Destruye toda la pool de socks */
void socks5_pool_destroy(void);

#endif