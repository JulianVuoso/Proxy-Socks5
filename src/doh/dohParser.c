#include <stdlib.h>
#include <ctype.h>

#include "dohParser.h"
#include "buffer.h"

#define DOH_CONTENT_STRING "CONTENT-"
#define DOH_LENGTH_STRING "LENGTH"
#define DOH_TYPE_STRING "TYPE"
#define DOH_APPLICATION_DNS_MESSAGE "APPLICATION/DNS-MESSAGE"

static DOHQRSM_STATE dohStatusLineParser(const char c, DOHQueryResSM *qrsm);
static DOHQRSM_STATE dohHeaderParser(const char c, DOHQueryResSM *qrsm);
static DOHQRSM_STATE dohBodyParser(const char c, DOHQueryResSM *qrsm);

void doh_parser_init(DOHQueryResSM *qrsm, enum connect_options option)
{
    qrsm->state = DOHQRSM_START;
    qrsm->nstate = DOHQRSM_START;
    qrsm->parser = dohStatusLineParser;
    qrsm->statusCode = 0;
    qrsm->contentLegth = 0;
    qrsm->res = 0;
    qrsm->aux2 = 0;
    qrsm->rCount = 0;
    qrsm->records = NULL;
    qrsm->option = option;
    return;
}

static DOHQRSM_STATE dohStatusLineParser(const char c, DOHQueryResSM *qrsm)
{
    switch (qrsm->state)
    {
    case DOHQRSM_START:
        if (c >= '0' && c <= '9')
        {
            qrsm->state = DOHQRSM_FIND_SPACE;
            qrsm->nstate = DOHQRSM_STATUS_CODE;
        }
        else if (c == '\n')
        {
            qrsm->state = DOHQRSM_ERROR;
        }

        break;
    case DOHQRSM_FIND_SPACE:
        if (c == ' ')
        {
            qrsm->state = qrsm->nstate;
        }
        else if (c == '\n')
        {
            qrsm->state = DOHQRSM_ERROR;
        }
        break;
    case DOHQRSM_STATUS_CODE:
        if (c >= '0' && c <= '9')
        {
            qrsm->statusCode = (qrsm->statusCode * 10) + (c - '0');
        }
        else if (c == '\n')
        {
            if (qrsm->statusCode / 100 != 2)
            {
                qrsm->state = DOHQRSM_ERROR;
            }
            else
            {
                qrsm->state = DOHQRSM_START;
                qrsm->parser = dohHeaderParser;
            }
        }
        break;
    // error state
    default:
        qrsm->state = DOHQRSM_ERROR;
        break;
    }
    return qrsm->state;
}
static DOHQRSM_STATE dohHeaderParser(const char c, DOHQueryResSM *qrsm)
{
    switch (qrsm->state)
    {
    case DOHQRSM_START:
        if (toupper(c) == DOH_CONTENT_STRING[0])
        {
            qrsm->state = DOHQRSM_MAYBE_CONTENT;
            qrsm->aux = 1;
        }
        else if (c == '\n')
        {
            if (qrsm->contentLegth > 0 && qrsm->contentLegth < 12)
            {
                qrsm->state = DOHQRSM_ERROR;
            }else{
                qrsm->state = DOHQRSM_START;
                qrsm->aux = 0;
                qrsm->parser = dohBodyParser;
            }
            
        }
        else if (!isspace(c))
        {
            qrsm->state = DOHQRSM_FIND_ENDLINE;
            qrsm->nstate = DOHQRSM_START;
        }

        break;
    case DOHQRSM_MAYBE_CONTENT:
        if (toupper(c) == DOH_CONTENT_STRING[qrsm->aux])
        {
            qrsm->aux++;
            if (qrsm->aux == sizeof(DOH_CONTENT_STRING) - 1)
            {
                qrsm->state = DOHQRSM_IS_CONTENT;
            }
        }
        else
        {
            qrsm->state = DOHQRSM_FIND_ENDLINE;
            qrsm->nstate = DOHQRSM_START;
        }
        break;
    case DOHQRSM_IS_CONTENT:
        if (toupper(c) == DOH_TYPE_STRING[0])
        {
            qrsm->state = DOHQRSM_MAYBE_CONTENT_TYPE;
            qrsm->aux = 1;
        }
        else if (toupper(c) == DOH_LENGTH_STRING[0])
        {
            qrsm->state = DOHQRSM_MAYBE_CONTENT_LENGTH;
            qrsm->aux = 1;
        }
        else if (c == ':')
        {
            qrsm->state = DOHQRSM_FIND_ENDLINE;
            qrsm->nstate = DOHQRSM_START;
        }
        else if (c == '\n')
        {
            qrsm->state = DOHQRSM_START;
        }
        break;
    case DOHQRSM_MAYBE_CONTENT_TYPE:
        if (c == '\n')
        {
            qrsm->state = DOHQRSM_START;
        }
        else if (toupper(c) == DOH_TYPE_STRING[qrsm->aux])
        {
            qrsm->aux++;
        }
        else if (c == ':')
        {
            if (qrsm->aux == sizeof(DOH_TYPE_STRING) - 1)
            {
                qrsm->state = DOHQRSM_IS_CONTENT_TYPE;
                qrsm->aux = 0;
            }
        }
        else
        {
            qrsm->state = DOHQRSM_FIND_ENDLINE;
            qrsm->nstate = DOHQRSM_START;
        }
        break;
    case DOHQRSM_MAYBE_CONTENT_LENGTH:
        if (c == '\n')
        {
            qrsm->state = DOHQRSM_START;
        }
        else if (toupper(c) == DOH_LENGTH_STRING[qrsm->aux])
        {
            qrsm->aux++;
        }
        else if (c == ':')
        {
            if (qrsm->aux == sizeof(DOH_LENGTH_STRING) - 1)
            {
                qrsm->state = DOHQRSM_IS_CONTENT_LENGTH;
                qrsm->aux = qrsm->contentLegth;
            }
        }
        else if (!isspace(c))
        {
            qrsm->state = DOHQRSM_FIND_ENDLINE;
            qrsm->nstate = DOHQRSM_START;
        }
        break;
    case DOHQRSM_IS_CONTENT_LENGTH:
        if (c >= '0' && c <= '9')
        {
            qrsm->contentLegth = (qrsm->contentLegth * 10) + (c - '0');
        }
        else if (c == '\n')
        {
            qrsm->state = DOHQRSM_START;
        }
        else if (!isspace(c))
        {
            qrsm->state = DOHQRSM_ERROR;
        }

        break;
    case DOHQRSM_IS_CONTENT_TYPE:
        if (c == '\n')
        {
            qrsm->state = DOHQRSM_START;
        }
        else if (!isspace(c) && ((unsigned long)qrsm->aux > sizeof(DOH_APPLICATION_DNS_MESSAGE) - 1 || toupper(c) != DOH_APPLICATION_DNS_MESSAGE[qrsm->aux++]))
        {
            qrsm->state = DOHQRSM_ERROR;
        }
        break;
    case DOHQRSM_FIND_ENDLINE:
        if (c == '\n')
        {
            qrsm->state = qrsm->nstate;
        }
        break;
    // error state
    default:
        qrsm->state = DOHQRSM_ERROR;
        break;
    }
    return qrsm->state;
}

static void findNextRR(DOHQueryResSM *qrsm)
{
    if (qrsm->header.qcount > 0)
    {
        qrsm->state = DOHQRSM_DNS_QUESTION;
    }
    else if (qrsm->header.ancount > 0)
    {
        qrsm->state = DOHQRSM_DNS_ANSWER;
        qrsm->aux = 0;
    }
    // commented because they are not needed
    // else if(qrsm->header.nscount>0){
    //     qrsm->state = DOHQRSM_DNS_NAMESERVER;
    // }else if(qrsm->header.arcount>0){
    //     qrsm->state = DOHQRSM_DNS_ADITIONAL;
    // }
    else
    {
        qrsm->state = DOHQRSM_EXIT;
    }
}

static DOHQRSM_STATE dohBodyParser(const char c, DOHQueryResSM *qrsm)
{
    switch (qrsm->state)
    {
    case DOHQRSM_START:
        switch (qrsm->aux)
        {
        case 0:
        case 1:
            break;
        //todo:should we consider AA
        //checking that the answer is in fact a response
        case 2:
            qrsm->state = !(c & 0x80) ? DOHQRSM_ERROR : qrsm->state;
            break;
        //check if error in response
        case 3:
            qrsm->state = (c & 0x0F) ? DOHQRSM_ERROR : qrsm->state;
            break;
        //qcount
        case 4:
            qrsm->header.qcount = ((uint16_t)(c & 0xFF)) << 8;
            break;
        case 5:
            qrsm->header.qcount += c & 0xFF;
            break;
        //ancount
        case 6:
            qrsm->header.ancount = ((uint16_t)(c & 0xFF)) << 8;
            break;
        case 7:
            qrsm->header.ancount += c & 0xFF;
            break;
        //nscount
        case 8:
            qrsm->header.nscount = ((uint16_t)(c & 0xFF)) << 8;
            break;
        case 9:
            qrsm->header.nscount += c & 0xFF;
            break;
        //arcount
        case 10:
            qrsm->header.arcount = ((uint16_t)(c & 0xFF)) << 8;
            break;
        //second part of arcount and next state initialize
        case 11:
            qrsm->header.arcount += c & 0xFF;
            findNextRR(qrsm);
            break;
        default:
            qrsm->state = DOHQRSM_ERROR;
            break;
        }
        qrsm->aux++;
        break;
    case DOHQRSM_DNS_QUESTION:
        //todo:check
        if (c == 0)
        {
            qrsm->header.qcount--;
            findNextRR(qrsm);
            qrsm->nstate = qrsm->state;
            qrsm->state = DOHQRSM_SKIP_N;
            qrsm->skip = 4;
        }
        break;
    case DOHQRSM_DNS_ANSWER:
        //contemplate compression
        qrsm->aux++;
        if(qrsm->aux == 1 && (c&0xC0)==0xC0){
            qrsm->skip = 1;
            qrsm->nstate = DOHQRSM_DNSTYPE;
            qrsm->state = DOHQRSM_SKIP_N;
            qrsm->aux = 0;
        }else if (c == 0)
        {
            qrsm->state = DOHQRSM_DNSTYPE;
            qrsm->aux = 0;
        }
        break;

    case DOHQRSM_DNSTYPE:
        if (qrsm->aux == 0)
        {
            qrsm->aux++;
            qrsm->aux2 = c;
        }
        else
        {
            qrsm->aux2 = (qrsm->aux2 << 8) + c;
            uint8_t dns_type = (qrsm->option == doh_ipv4) ? DNSTYPE_IPV4 : DNSTYPE_IPV6;
            if (qrsm->aux2 != dns_type)
            {
                qrsm->skip = 6;
                qrsm->state = DOHQRSM_SKIP_N;
                qrsm->nstate = DOHQRSM_SKIP_RDLENGTH;
            }
            else
            {
                qrsm->state = DOHQRSM_DNSCLASS;
            }
            qrsm->aux = 0;
        }
        break;
    case DOHQRSM_DNSCLASS:
        if (qrsm->aux == 0)
        {
            qrsm->aux++;
            qrsm->aux2 = c;
        }
        else
        {
            qrsm->aux2 = (qrsm->aux2 << 8) + c;
            if (qrsm->aux2 != SHOULD_BE_DNSCLASS)
            {
                qrsm->skip = 4;
                qrsm->state = DOHQRSM_SKIP_N;
                qrsm->nstate = DOHQRSM_SKIP_RDLENGTH;
            }
            else
            {
                qrsm->skip = 4;
                qrsm->state = DOHQRSM_SKIP_N;
                qrsm->nstate = DOHQRSM_RDLENGTH;
            }
            qrsm->aux = 0;
        }
        break;
    case DOHQRSM_RDLENGTH:
        if (qrsm->aux == 0)
        {
            qrsm->aux++;
            qrsm->aux2 = c;
        }
        else
        {
            qrsm->aux2 = (qrsm->aux2 << 8) + c;
            if (qrsm->aux2 > 0)
            {
                //TODO: CHECK IF REALLOC OF NULL IS A GOOD IDEA
                qrsm->rCount++;
                void *aux = realloc(qrsm->records, qrsm->rCount * sizeof(DNSResRec));
                if (aux == NULL)
                {
                    qrsm->state = DOHQRSM_ERROR;
                }
                else
                {
                    qrsm->records = aux;
                    qrsm->records[qrsm->rCount - 1].rdlength = qrsm->aux2;
                    qrsm->records[qrsm->rCount - 1].rddata = malloc(qrsm->aux2 * sizeof(DNSResRec));
                    if (qrsm->records[qrsm->rCount - 1].rddata == NULL)
                    {
                        qrsm->state = DOHQRSM_ERROR;
                    }
                    else
                    {
                        qrsm->state = DOHQRSM_RDDATA;
                    }
                }
            }
            else
            {
                qrsm->state = DOHQRSM_DNS_ANSWER;
                qrsm->aux = 0;
            }
            qrsm->aux = 0;
        }
        break;
    case DOHQRSM_RDDATA:
        if(qrsm->aux2 < 1){
            qrsm->header.ancount--;
            findNextRR(qrsm);
        }if (qrsm->aux2 <= 1)
        {
            //add to last record the next c
            qrsm->records[qrsm->rCount - 1].rddata[qrsm->records[qrsm->rCount - 1].rdlength - qrsm->aux2] = c;
            qrsm->header.ancount--;
            findNextRR(qrsm);
        }
        else
        {
            //add to last record the next c
            qrsm->records[qrsm->rCount - 1].rddata[qrsm->records[qrsm->rCount - 1].rdlength - qrsm->aux2] = c;
            //one less character to read
            qrsm->aux2--;
        }
        break;
    case DOHQRSM_SKIP_N:
        qrsm->skip--;
        if (qrsm->skip < 1)
        {
            qrsm->state = qrsm->nstate;
        }
        break;
    case DOHQRSM_SKIP_RDLENGTH:
        if(qrsm->aux==0){
            qrsm->aux2 = c;
            qrsm->aux++;
        }else{
            qrsm->aux2 = (qrsm->aux2<<8) + c;
            qrsm->skip = qrsm->aux2;
            findNextRR(qrsm);
            qrsm->nstate = qrsm->state; 
            qrsm->state = DOHQRSM_SKIP_N;
            qrsm->header.ancount--;
        }
        break;
    // error state
    default:
        qrsm->state = DOHQRSM_ERROR;
        break;
    }
    return qrsm->state;
}

DOHQRSM_STATE dohParse(const char c, DOHQueryResSM *qrsm) {
    //if error return inmediately
    if (qrsm == NULL || doh_parser_is_done(qrsm->state, 0)) {
        return qrsm->state;
    }
    return (*(qrsm->parser))(c, qrsm);
}

DOHQRSM_STATE doh_parser_consume(buffer * b, DOHQueryResSM *qrsm, bool * errored) {
    if (qrsm == NULL) {
        if (errored != NULL) {
            *errored = true;
        }
        return DOHQRSM_ERROR;
    }

    DOHQRSM_STATE state = qrsm->state;
    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        state = dohParse(c, qrsm);
        if (doh_parser_is_done(state, errored)) {
            break;
        }
    }
    return state;
}

bool doh_parser_is_done(DOHQRSM_STATE state, bool * errored) {
    bool ret;
    switch (state)
    {
        case DOHQRSM_ERROR:
            if (errored != NULL) {
                *errored = true;
            }
            ret = true;
            break;
        case DOHQRSM_EXIT:
            if (errored != NULL) {
                *errored = false;
            }
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
    return ret;
}

void freeDohParser(DOHQueryResSM *qrsm){
    if (qrsm == NULL) return;

    for (int i = 0; i < qrsm->rCount; i++)
    {
        if(qrsm->records[i].rddata != NULL){
            free(qrsm->records[i].rddata);
        }
    }
    if (qrsm->records != NULL) {
        free(qrsm->records);
    }
}