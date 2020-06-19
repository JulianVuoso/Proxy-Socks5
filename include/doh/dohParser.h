#ifndef __PROTOS_DOH_PARSER__
#define __PROTOS_DOH_PARSER__
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "doh_answer_struct.h"

//type of dns we are looking for
// 1 = A
#define SHOULD_BE_DNSTYPE 1
//class of dns we are looking for
// 1 = A
#define SHOULD_BE_DNSCLASS 1


void doh_parser_init(DOHQueryResSM *qrsm);
// void statusLineParser(const char c, DOHQueryResSM *qrsm);
// void headerParser(const char c, DOHQueryResSM *qrsm);
// void bodyParser(const char c, DOHQueryResSM *qrsm);
DOHQRSM_STATE dohParse(const char c, DOHQueryResSM *qrsm);
DOHQRSM_STATE doh_parser_consume(buffer * b, DOHQueryResSM *qrsm, bool * errored);
bool doh_parser_is_done(DOHQRSM_STATE state, bool * errored);
void freeDohParser(DOHQueryResSM *qrsm);

#endif