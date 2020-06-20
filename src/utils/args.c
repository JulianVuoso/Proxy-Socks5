#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h> /* Address families */
#include <string.h>
#include <ctype.h>

#include "args.h"

#define IPV4_REGEX "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}"

static unsigned short
port(const char *s) {
     char *end     = 0;
     const long sl = strtol(s, &end, 10);

     if (end == s|| '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX) {
         fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
         exit(1);
         return 1;
     }
     return (unsigned short)sl;
}

static void
add_user_client(char *s) {
    // uint8_t * token = (uint8_t *)strtok(s, SEPARATOR), *user, *pass, i = 0;    

    // user = malloc(sizeof(token));
    // if (user == NULL) exit(1);
    // strcpy((char *)user, (char *)token); 

    // token = (uint8_t *)strchr(NULL, SEPARATOR);
    // if(token == NULL){
    //     fprintf(stderr, "password not found\n");
    //     exit(1);
    // }
    // pass = malloc(sizeof(token));
    // if(pass == NULL) exit(1);
    // strcpy((char *)pass, (char *)token); 
    
    // add_user_to_list(user, pass, CLIENT);
}

static void
add_user(char* s) {
    uint8_t * token = (uint8_t *)strtok(s, SEPARATOR), *user, *pass, i = 0, level;    
    while(token)
    {
        switch (i)
        {
            case 0: user = malloc(sizeof(token));
                    if (user == NULL) exit(1);
                    strcpy((char *)user, (char *)token); 
                    i++; 
                    break;
            case 1: pass = malloc(sizeof(token));
                    if(pass == NULL) exit(1);
                    strcpy((char *)pass, (char *)token); 
                    i++; 
                    break;
            case 2: level = atoi((char *)token); 
                    printf("LEVEL: %s", token);
                    if((level != CLIENT && level != ADMIN)||(!isdigit(*token))){
                        fprintf(stderr, "invalid user level (0:client 1:admin) \n");        
                        exit(1);
                    }
                    add_user_to_list(user, pass, level);
                    i = 0; 
                    break;
            default: break;
        }
        token = (uint8_t *)strtok(NULL, SEPARATOR);
        if(token == NULL){
            if(i==1) {
                fprintf(stderr, "password not found\n");        
                exit(1);
            }
            if(i==2){
                fprintf(stderr, "user level not found\n");        
                exit(1);
            }
        }
    }
}

static void
version(void) {
    fprintf(stderr, "socks5v version 0.0\n"
                    "ITBA Protocolos de Comunicación 2020/1 -- Grupo X\n"
                    "AQUI VA LA LICENCIA\n");
}

static void
usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTION]...\n"
        "\n"
        "   -h                        Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>           Dirección donde servirá el proxy SOCKS.\n"
        "   -L <conf  addr>           Dirección donde servirá el servicio de management.\n"
        "   -p <SOCKS port>           Puerto entrante conexiones SOCKS.\n"
        "   -P <conf port>            Puerto entrante conexiones configuracion\n"
        "   -u <name>:<pass>          Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
        "   -U <name>:<pass>:<utype>  Usuario, contraseña y tipo de usuario que puede usar el proxy. Hasta 10.\n"
        "   -v                        Imprime información sobre la versión versión y termina.\n"
        "\n"
        "   --doh-ip    <ip>    \n"
        "   --doh-port  <port>  XXX\n"
        "   --doh-host  <host>  XXX\n"
        "   --doh-path  <host>  XXX\n"
        "   --doh-query <host>  XXX\n"

        "\n",
        progname);
    exit(1);
}

void 
parse_args(const int argc, const char **argv, struct socks5args *args) {
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->socks_addr = "0.0.0.0";
    args->socks_port = 1080;

    args->mng_addr   = "127.0.0.1";
    args->mng_port   = 8080;

    args->disectors_enabled = true;

    args->doh.host = "localhost";
    args->doh.ip   = "127.0.0.1";
    args->doh.ip_family = AF_INET;
    args->doh.port = 8053;
    args->doh.path = "/getnsrecord";
    args->doh.query = "?dns=";

    int c;
    int nusers = 0;

    while (true) {
        int option_index = 0;
        static struct option long_options[] = {
            { "doh-ip",    required_argument, 0, 0xD001 },
            { "doh-port",  required_argument, 0, 0xD002 },
            { "doh-host",  required_argument, 0, 0xD003 },
            { "doh-path",  required_argument, 0, 0xD004 },
            { "doh-query", required_argument, 0, 0xD005 },
            { 0,           0,                 0, 0 }
        };

        c = getopt_long(argc, (char * const *) argv, "hl:L:Np:P:u:U:v", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'l':
                args->socks_addr = optarg;
                break;
            case 'L':
                args->mng_addr = optarg;
                break;
            case 'N':
                args->disectors_enabled = false;
                break;
            case 'p':
                args->socks_port = port(optarg);
                break;
            case 'P':
                args->mng_port   = port(optarg);
                break;
            case 'u':
                if(nusers >= MAX_USERS) {
                    fprintf(stderr, "maximun number of command line users reached: %d.\n", MAX_USERS);
                    exit(1);
                } else {
                    add_user_client(optarg);
                }
                break;
            case 'U':
                if(nusers >= MAX_USERS) {
                    fprintf(stderr, "maximun number of command line users reached: %d.\n", MAX_USERS);
                    exit(1);
                } else {
                    add_user(optarg);
                }
                break;
            case 'v':
                version();
                exit(0);
                break;
            case 0xD001:
                args->doh.ip = optarg;
                /** TODO: ver como hacer para validar que sea IPv4 o IPv6 */
                args->doh.ip_family = AF_INET;
                break;
            case 0xD002:
                args->doh.port = port(optarg);
                break;
            case 0xD003:
                args->doh.host = optarg;
                break;
            case 0xD004:
                args->doh.path = optarg;
                break;
            case 0xD005:
                args->doh.query = optarg;
                break;
            default:
                fprintf(stderr, "unknown argument %d.\n", c);
                exit(1);
        }
        print_users();
    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}
