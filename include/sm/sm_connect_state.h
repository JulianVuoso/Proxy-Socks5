#ifndef SM_CONNECT_STATE_H_d17d785c985138358c0992ac64056076084e18aa
#define SM_CONNECT_STATE_H_d17d785c985138358c0992ac64056076084e18aa

#include "dohclient.h"
#include "selector.h"
#include "doh_server_struct.h"

/* First doh connect (initi and connect) */
unsigned start_doh_connect(struct selector_key * key);

/* Next doh connect (no init) */
unsigned connect_doh_server(struct selector_key * key);

unsigned prepare_blocking_doh(struct selector_key * key);

unsigned dns_connect_write(struct selector_key * key);

unsigned dns_write(struct selector_key *key);

void dns_read_init(const unsigned state, struct selector_key *key);

unsigned dns_read(struct selector_key *key);

unsigned dns_answer_process(struct selector_key *key, bool errored);

unsigned try_next_option(struct selector_key * key);

unsigned request_solve_block(struct selector_key *key);

#endif