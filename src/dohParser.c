void statusLineParser(const char c, DOHQueryResSM *qrsm);
void headerParser(const char c, DOHQueryResSM *qrsm);
void bodyParser(const char c, DOHQueryResSM *qrsm);

void initParser(DOHQueryResSM *qrsm)
{
    qrsm->state = DOHQRSM_START;
    qrsm->nstate = DOHQRSM_START;
    qrsm->parser = statusLineParser;
    qrsm->statusCode = 0;
    qrsm->res = 0;
    return;
}

void statusLineParser(const char c, DOHQueryResSM *qrsm)
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
                qrsm->parser = headerParser;
            }
        }
        break;
    }
}
void headerParser(const char c, DOHQueryResSM *qrsm)
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
            qrsm->state = DOHQRSM_START;
            qrsm->parser = bodyParser;
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
        }else if(c == ':'){
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
        else if (!isspace(c) && (qrsm->aux > sizeof(DOH_APPLICATION_DNS_MESSAGE) - 1 || toupper(c) != DOH_APPLICATION_DNS_MESSAGE[qrsm->aux++]))
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
    }
}

void bodyParser(const char c, DOHQueryResSM *qrsm){
    //TODO: implement
}

void dohParse(const char c, DOHQueryResSM *qrsm)
{
    //if error return inmediately
    if (qrsm == NULL || qrsm->state == DOHQRSM_ERROR)
    {
        return;
    }
    (*(qrsm->parser))(c, qrsm);
}
