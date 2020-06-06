#ifndef __DNS_LOOK_UP__
#define __DNS_LOOK_UP__
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

typedef struct{
    size_t length;
    char *query;
}BASE64DNSQuery;

/*
    params:
        -fqdn: String input
        -query: BASE64DNSQuery output
    returns:
        -0 if succesful
        -another number if not
*/
int getQuery(const char *fqdn,BASE64DNSQuery *query);

#endif