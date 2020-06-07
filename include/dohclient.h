#ifndef __PROTOS_DOH_CLIENT__
#define __PROTOS_DOH_CLIENT__
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define PORT 80
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
int dnsLookUp(const char *fqdn);

#endif