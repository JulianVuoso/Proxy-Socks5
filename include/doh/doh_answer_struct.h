#ifndef DOH_ANSWER_STRUCT_H_21a750ff3332497f063ce7e94e6f829cfcb1216a
#define DOH_ANSWER_STRUCT_H_21a750ff3332497f063ce7e94e6f829cfcb1216a

#include <stdint.h>
#include "doh_server_struct.h"

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
    DOHQRSM_STATE (*parser)(const char,struct DOHQueryResSM*);
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
    enum connect_options option;
}DOHQueryResSM;

#endif