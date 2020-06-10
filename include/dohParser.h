#ifndef __PROTOS_DOH_PARSER__
#define __PROTOS_DOH_PARSER__
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "dohclient.h"



typedef enum{
    //general purpose
    DOHQRSM_EXIT = 0,
    DOHQRSM_START,
    DOHQRSM_ERROR,
    DOHQRSM_FIND_SPACE,
    DOHQRSM_FIND_ENDLINE,
    DOHQRSM_LINE_NOT_EMPTY,
    
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

} DOHQRSM_STATE;

typedef struct DOHQueryResSM{
    DOHQRSM_STATE state;
    DOHQRSM_STATE nstate;
    void (*parser)(const char,struct DOHQueryResSM*);
    int res;
    int aux;
    int contentLegth;
    int statusCode;
}DOHQueryResSM;

void initParser(DOHQueryResSM *qrsm);
void statusLineParser(const char c, DOHQueryResSM *qrsm);
void headerParser(const char c, DOHQueryResSM *qrsm);
void bodyParser(const char c, DOHQueryResSM *qrsm);
void dohParse(const char c, DOHQueryResSM *qrsm);


#endif