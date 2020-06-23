#ifndef ADMIN_SOCKS5_H_46ce465da9d3e46f7c0e73bbd1d48df2d7a1e0d2
#define ADMIN_SOCKS5_H_46ce465da9d3e46f7c0e73bbd1d48df2d7a1e0d2

#include "selector.h"

#define MAX_CONCURRENT_CON_ADMIN    400

/* Recibe la llave del item */
void admin_passive_accept(selector_key * key);
/* Destruye toda la pool de socks */
/* void admin_pool_destroy(void); */

#endif