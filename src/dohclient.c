#include "dohclient.h"
#define DNS_HEADER_LENGTH 12
#define DNS_QUERY_LENGTH(fqdnLength) ((fqdnLength) + 1 + 1 + 4)
#define DNS_HEADER_BASE64 "AAABAAABAAAAAAAA"
#define DNS_HEADER_BASE64_LENGTH sizeof(DNS_HEADER_BASE64)
//without null termination
#define BASE64URL_LENGTH(len) ((((len) + 2) / 3) * 4)

#define HTTP_QUERY_START "GET /dns-query?dns="
#define HTTP_QUERY_END " HTTP/1.1\r\nhost:localhost\r\naccept:application/dns-message\r\n\r\n"


// BASE64URL
// Value Encoding  Value Encoding  Value Encoding  Value Encoding
//         0 A            17 R            34 i            51 z
//         1 B            18 S            35 j            52 0
//         2 C            19 T            36 k            53 1
//         3 D            20 U            37 l            54 2
//         4 E            21 V            38 m            55 3
//         5 F            22 W            39 n            56 4
//         6 G            23 X            40 o            57 5
//         7 H            24 Y            41 p            58 6
//         8 I            25 Z            42 q            59 7
//         9 J            26 a            43 r            60 8
//        10 K            27 b            44 s            61 9
//        11 L            28 c            45 t            62 - (minus)
//        12 M            29 d            46 u            63 _ (underline)
//        13 N            30 e            47 v            (pad) =
//        14 O            31 f            48 w
//        15 P            32 g            49 x
//        16 Q            33 h            50 y
//    https://tools.ietf.org/html/rfc4648 section 5

char *base64encoder = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// DNS HEADER
//   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// https://tools.ietf.org/html/rfc1035 section 4.1.1

// DNS QUERY
//   0  1  2  3  4  5  6  7  8  9  0 11 12 13 14 15
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                     QNAME                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QTYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QCLASS                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// https://tools.ietf.org/html/rfc1035 section 4.1.2

// DNS RESPONSE
//   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                                               /
// /                      NAME                     /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TTL                      |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   RDLENGTH                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                     RDATA                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// https://tools.ietf.org/html/rfc1035 section 4.1.3

//create query string
int getQuery(const char *fqdn, BASE64DNSQuery *query)
{
    //create de qname for dns query
    int fqdnLen = strlen(fqdn);
    uint8_t queryBod[DNS_QUERY_LENGTH(fqdnLen)];
    int i, save;
    for (i = 1, save = 0; i < fqdnLen + 1; i++)
    {
        //change stop for the length of the queryBod
        if (fqdn[i - 1] == '.')
        {
            queryBod[save] = (i - 1) - save;
            save = i;
        }
        else
        {
            queryBod[i] = fqdn[i - 1];
        }
    }
    //if address didnt have a stop at the end
    if (save != i-1)
    {
        queryBod[save] = (i - 1) - save;
        queryBod[i] = 0;i++;
    }
    else
    {
        fqdnLen -= 1;
        queryBod[i-1]=0;
    }
    queryBod[i] = 0x00;i++;
    queryBod[i] = 0x01;i++;
    queryBod[i] = 0x00;i++;
    queryBod[i] = 0x01;i++;

    //malloc query
    query->length = BASE64URL_LENGTH(DNS_QUERY_LENGTH(fqdnLen) + DNS_HEADER_LENGTH);
    query->query = malloc(query->length);
    if (query == NULL)
    {
        return -1;
    }

    int pos = 0;
    //cpy query
    memcpy(query->query, DNS_HEADER_BASE64, DNS_HEADER_BASE64_LENGTH - 1);
    pos += DNS_HEADER_BASE64_LENGTH-1;
    int j;
    for (j = 0; j < (i / 3); j++)
    {
        //get the 6 most significant bits
        query->query[pos++] = base64encoder[(queryBod[(j * 3)] >> 2) & 0x3F];
        //get the 2 least significant of the first and the 4 more significant of the second
        query->query[pos++] = base64encoder[(((queryBod[(j * 3)] << 4) & 0x30) | ((queryBod[(j * 3) + 1] >> 4) & 0x0F)) & 0x3F];
        //get the 4 least significant of the first and the 2 most significant of the second
        query->query[pos++] = base64encoder[(((queryBod[(j * 3) + 1] << 2) & 0x3C) | ((queryBod[(j * 3) + 2] >> 6) & 0x03)) & 0x3F];
        //get the 6 least significant bits
        query->query[pos++] = base64encoder[queryBod[(j * 3) + 2] & 0x3F];
    }
    //could have a realloc
    if (i % 3 == 1)
    {
        query->query[pos++] = base64encoder[(queryBod[i - 1] >> 2) & 0x3F];
        query->query[pos++] = base64encoder[(queryBod[(j * 3)] << 4) & 0x30];
        query->length -= 2;
    }
    else if (i % 3 == 2)
    {
        query->query[pos++] = base64encoder[(queryBod[i - 2] >> 2) & 0x3F];
        query->query[pos++] = base64encoder[(((queryBod[i-2] << 4) & 0x30) | ((queryBod[i-1] >> 4) & 0x0F)) & 0x3F];
        query->query[pos++] = base64encoder[(queryBod[(j * 3) + 1] << 2) & 0x3C];
        query->length -= 1;
    }
    query->query[pos] = 0;
    query->length = pos;
    return 0;
}



int dnsLookUp(const char *fqdn,DOHQueryResSM *qrsm)
{
    //variables
    int sockfd = -1;
    struct sockaddr_in address;
    BASE64DNSQuery query;
    int buffdim = 100;
    char buffer[buffdim];
    query.query = NULL;
    query.length = -1;
    
    //create the query
    if(getQuery(fqdn,&query)){
        perror("failed to create query");
        goto error;
    }

    //create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("failed socket creation");
        goto error;
    }

    //create address
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) <= 0)
    {
        perror("problema con la direccion");
        goto error;
    }

    //connect to address
    if (connect(sockfd, (struct sockaddr*)&address, sizeof(address)) < 0)
    {
        perror("no se pudo conectar");
        goto error;
    }

    //send query
    send(sockfd,HTTP_QUERY_START,sizeof(HTTP_QUERY_START)-1,MSG_MORE);
    send(sockfd,query.query,query.length,MSG_MORE);
    send(sockfd,HTTP_QUERY_END,sizeof(HTTP_QUERY_END),0);

    //parse response
    int readed;
    initParser(qrsm);
    while (qrsm->state != DOHQRSM_ERROR && qrsm->state != DOHQRSM_EXIT && (readed = read(sockfd,buffer,buffdim))!=0)
    {
        for (int i = 0; i < readed; i++)
        {
            dohParse(buffer[i],qrsm);
        }
        
    }
    //free resources and exit
    close(sockfd);
    free(query.query);
    return 0;
error:
    if (sockfd > 0)
    {
        close(sockfd);
    }
    if (query.query != NULL)
    {
        free(query.query);
    }
    return -1;
}