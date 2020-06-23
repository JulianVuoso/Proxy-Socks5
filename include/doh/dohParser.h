#ifndef __PROTOS_DOH_PARSER__
#define __PROTOS_DOH_PARSER__
#include <stdbool.h>
// #include <sys/socket.h>
// #include <arpa/inet.h>
// #include <unistd.h>
// #include <string.h>

#include "doh_answer_struct.h"
#include "buffer.h"

//type of dns we are looking for
// 1 = A
#define DNSTYPE_IPV4        0x01
#define DNSTYPE_IPV6        0x1C
//class of dns we are looking for
// 1 = A
#define SHOULD_BE_DNSCLASS  1


void doh_parser_init(DOHQueryResSM *qrsm, enum connect_options option);
// void statusLineParser(const char c, DOHQueryResSM *qrsm);
// void headerParser(const char c, DOHQueryResSM *qrsm);
// void bodyParser(const char c, DOHQueryResSM *qrsm);
DOHQRSM_STATE dohParse(const char c, DOHQueryResSM *qrsm);
DOHQRSM_STATE doh_parser_consume(buffer * b, DOHQueryResSM *qrsm, bool * errored);
bool doh_parser_is_done(DOHQRSM_STATE state, bool * errored);
void freeDohParser(DOHQueryResSM *qrsm);

#endif