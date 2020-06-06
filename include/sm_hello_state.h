#ifndef SM_HELLO_STATE_H_aac2b6cf6bed1416a06cd5d497c63efc5a5bc3a1
#define SM_HELLO_STATE_H_aac2b6cf6bed1416a06cd5d497c63efc5a5bc3a1

#include "hello.h"
#include "selector.h"

// HELLO_READ y HELLO_WRITE
typedef struct hello_st {
    buffer * read_buf, * write_buf;
    struct hello_parser parser;
    /* Metodo de autenticacion seleccionado */
    uint8_t method;
} hello_st;

/* Inicializa las variables de los estados HELLO_READ y HELLO_WRITE */
void hello_read_init(const unsigned state, struct selector_key *key);
unsigned hello_read(struct selector_key *key);
void hello_read_close(const unsigned state, struct selector_key *key);

unsigned hello_process(const struct hello_st * d);

void hello_write_init(const unsigned state, struct selector_key *key);
unsigned hello_write(struct selector_key *key);
void hello_write_close(const unsigned state, struct selector_key *key);

#endif