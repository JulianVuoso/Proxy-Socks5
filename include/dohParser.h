#ifndef __PROTOS_DOH_PARSER__
#define __PROTOS_DOH_PARSER__
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "dohclient.h"

//type of dns we are looking for
// 1 = A
#define SHOULD_BE_DNSTYPE 1
//class of dns we are looking for
// 1 = A
#define SHOULD_BE_DNSCLASS 1

typedef enum{
    //general purpose
    DOHQRSM_EXIT = 0,
    DOHQRSM_START,
    DOHQRSM_ERROR,
    DOHQRSM_FIND_SPACE,
    DOHQRSM_FIND_ENDLINE,
    DOHQRSM_LINE_NOT_EMPTY,
    DOHQRSM_SKIP_N,
    
    //firstline parser
    DOHQRSM_STATUS_CODE,

    //headerParser
    DOHQRSM_MAYBE_CONTENT,
    DOHQRSM_IS_CONTENT,
    DOHQRSM_FIND_MAYBE_ENDING_HEADER,
    DOHQRSM_MAYBE_CONTENT_TYPE,
    DOHQRSM_MAYBE_CONTENT_LENGTH,
    DOHQRSM_IS_CONTENT_TYPE,
    DOHQRSM_IS_CONTENT_LENGTH,

    //bodyParser
    DOHQRSM_DNS_QUESTION,
    DOHQRSM_DNS_ANSWER,
    // DOHQRSM_DNS_NAMESERVER,    // NOT
    // DOHQRSM_DNS_ADITIONAL,    // NEEDED

    DOHQRSM_DNSTYPE,
    DOHQRSM_DNSCLASS,
    DOHQRSM_RDLENGTH,
    DOHQRSM_RDDATA,

    DOHQRSM_SKIP_RDLENGTH

} DOHQRSM_STATE;

typedef struct DNSQueryHeader
{
    //id and control skipped as not needed
    uint16_t qcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
}DNSQueryHeader;

typedef struct DNSResRec
{
    // int startOffset;    //not needed
    // int length;         //not needed
    // char *name;         //not needed
    // uint16_t TTL;       //not needed 
    // uint16_t dnstype;   //not needed
    // uint8_t dnsclass;   //not needed
    uint16_t rdlength;  
    char *rddata;       
}DNSResRec;

typedef struct DOHQueryResSM{
    DOHQRSM_STATE state;
    DOHQRSM_STATE nstate;
    void (*parser)(const char,struct DOHQueryResSM*);
    int res;
    int aux;
    int contentLegth;
    int statusCode;
    int skip;
    DNSQueryHeader header;
    DNSResRec *records;
    //used in body
    int aux2;
    int rCount;
}DOHQueryResSM;

void initParser(DOHQueryResSM *qrsm);
void statusLineParser(const char c, DOHQueryResSM *qrsm);
void headerParser(const char c, DOHQueryResSM *qrsm);
void bodyParser(const char c, DOHQueryResSM *qrsm);
void dohParse(const char c, DOHQueryResSM *qrsm);
void freeDohParser(DOHQueryResSM *qrsm);

#endif