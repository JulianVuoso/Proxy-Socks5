#ifndef __PROTOS_DOH_CLIENT__
#define __PROTOS_DOH_CLIENT__
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "doh_answer_struct.h"
#include "doh_server_struct.h"
#include "buffer.h"

#define PORT 80

typedef struct{
    size_t length;
    char *query;
}BASE64DNSQuery;

int doh_query_marshall(buffer * b, const char * fqdn, const struct doh doh_info, enum connect_options option);

int dnsLookUp(const char *fqdn,struct DOHQueryResSM *qrsm);

#endif