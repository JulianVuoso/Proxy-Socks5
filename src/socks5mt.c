#include <stdio.h>

#include "socks5mt.h"
#include "hello.h"
#include "selector.h"

void error_arrival(const unsigned state, struct selector_key *key) {
    puts("ERROR");
}