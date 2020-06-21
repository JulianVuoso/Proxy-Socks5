#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#include "selector.h"
#include "socks5.h"
#include "admin_socks5.h"
#include "users.h"
#include "logger.h"
#include "args.h"
#include "doh_server_struct.h"

/** TODO: SACAR CUANDO CORRIJAMOS lo de char * a  */
#define IPV6_ADDRESS    "::"

#define USERS_FILENAME  "users.txt"

#define LOGGER_FD       1
#define LOGGER_LEVEL    DEBUG

enum socket_errors { socket_no_error, error_socket_create, error_socket_bind, error_socket_listen, error_invalid_address, error_socket_sockopt};

static unsigned create_socket_ipv4(const char *  address, unsigned port, int * server_fd);
static unsigned create_socket_ipv6(const char * address, unsigned port, int * server_fd);
static unsigned create_admin_socket(const char * address, unsigned port, int * admin_fd);
static const char * socket_error_description(enum socket_errors error);
static const char * file_error_description(enum file_errors error);

static bool done = false;

/** TODO: Ver como libero recursos en este caso  */
static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int
main(const int argc, const char **argv) {

    /* Try to read users file */
    enum file_errors file_state = read_users_file(USERS_FILENAME);
    if(file_state != file_no_error){
        fprintf(stdout, "Users file read failed. Error: %s\n", file_error_description(file_state));
    }

    /* Parse args */
    struct socks5args args;
    parse_args(argc, argv, &args);
    set_doh_info(args.doh);
    
    const char * err_msg = NULL;

    close(0);

    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;

    int server_ipv4, server_ipv6, server_admin;
    
    enum socket_errors error_ipv4 = create_socket_ipv4(args.socks_addr, args.socks_port, &server_ipv4);
    if (error_ipv4 != socket_no_error) {
        err_msg = socket_error_description(error_ipv4);
        goto finally;
    }
    // TODO check ipv6 address handling by args
    enum socket_errors error_ipv6 = create_socket_ipv6(IPV6_ADDRESS, args.socks_port, &server_ipv6);
    if (error_ipv6 != socket_no_error) {
        err_msg = socket_error_description(error_ipv6);
        goto finally;
    }
    
    enum socket_errors error_admin = create_admin_socket(args.mng_addr, args.mng_port, &server_admin);
    if (error_admin != socket_no_error) {
        err_msg = socket_error_description(error_admin);
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %u\n", args.socks_port);

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    if(selector_fd_set_nio(server_ipv4) == -1 || 
        selector_fd_set_nio(server_ipv6) == -1 ||
            selector_fd_set_nio(server_admin) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }
    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };
    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if(selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }

    /* Initialize logger */
    // enum logger_level level = DEBUG;
    // if (args.disectors_enabled) level = PASS_LOG; 
    // ss = logger_init(LOGGER_FD, level, selector);
    ss = logger_init(LOGGER_FD, LOGGER_LEVEL, selector); // TODO: uncomment prev on production


    const struct fd_handler socks5 = {
        .handle_read       = socks5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    if (ss == SELECTOR_SUCCESS) {
        ss = selector_register(selector, server_ipv4, &socks5,
                                              OP_READ, NULL);
    }
    if (ss == SELECTOR_SUCCESS) {
        ss = selector_register(selector, server_ipv6, &socks5,
                                              OP_READ, NULL);
    }
    const struct fd_handler admin_handlers = {
        .handle_read       = admin_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    if (ss == SELECTOR_SUCCESS) {
        ss = selector_register(selector, server_admin, &admin_handlers,
                                              OP_READ, NULL);
    }
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }
    for(;!done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
        /** TODO: Agregar timeout */
    }

    file_state = update_users_file(USERS_FILENAME);
    if(file_state != file_no_error){
        fprintf(stdout, "Users file updating failed. Error: %s\n", file_error_description(file_state));
    }

    if(err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;
finally:
    if(ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "": err_msg,
                                  ss == SELECTOR_IO
                                      ? strerror(errno)
                                      : selector_error(ss));
        ret = 2;
    } else if(err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    // socks5_pool_destroy();

    if(server_ipv4 >= 0) {
        close(server_ipv4);
    }
    if(server_ipv6 >= 0) {
        close(server_ipv6);
    }
    if(server_admin >= 0) {
        close(server_admin);
    }

    free_users_list();
    
    return ret;
}

static unsigned 
create_socket_ipv4(const char * address, unsigned port, int * server_fd) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    if (inet_pton(AF_INET, address, &addr.sin_addr) == 0) {
        return error_invalid_address;
    }

    *server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*server_fd < 0) {
        return error_socket_create;
    }
    // man 7 ip. no importa reportar nada si falla.
    setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    if(bind(*server_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        return error_socket_bind;
    }

    if (listen(*server_fd, 20) < 0) {
        return error_socket_listen;
    }

    return socket_no_error;
}

static unsigned 
create_socket_ipv6(const char * address, unsigned port, int * server_fd) {
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family      = AF_INET6;
    addr.sin6_port        = htons(port);
    if (inet_pton(AF_INET6, address, &addr.sin6_addr) == 0) {
        return error_invalid_address;
    }
    
    *server_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (*server_fd < 0) {
        return error_socket_create;
    }
    
    // man 7 ip. no importa reportar nada si falla.
    setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    if (setsockopt(*server_fd, SOL_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int)) < 0) {
        return error_socket_sockopt;
    }

    if(bind(*server_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        return error_socket_bind;
    }

    if (listen(*server_fd, 20) < 0) {
        return error_socket_listen;
    }

    return socket_no_error;
}

static unsigned
create_admin_socket(const char * address, unsigned port, int * admin_fd) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    if (inet_pton(AF_INET, address, &addr.sin_addr) == 0) {
        return error_invalid_address;
    }

    *admin_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (*admin_fd < 0) {
        return error_socket_create;
    }
    // man 7 ip. no importa reportar nada si falla.
    // setsockopt(*admin_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    struct sctp_initmsg initmsg;
    memset(&initmsg, 0, sizeof(initmsg));
    initmsg.sinit_num_ostreams = 1;
    initmsg.sinit_max_instreams = 1;
    initmsg.sinit_max_attempts = 4;
    if (setsockopt(*admin_fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) < 0) {
        return error_socket_sockopt;
    }
    
    if(bind(*admin_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        return error_socket_bind;
    }

    if (listen(*admin_fd, 20) < 0) {
        return error_socket_listen;
    }

    return socket_no_error;
}

static const char * socket_error_description(enum socket_errors error) {
    char * ret;
    switch (error)
    {
        case error_socket_create:
            ret = "unable to create socket";
            break;
        case error_socket_bind:
            ret = "unable to bind socket";
            break;
        case error_socket_listen:
            ret = "unable to listen socket";
            break;
        case error_socket_sockopt:
            ret = "unable to set sockopt";
            break;
        default:
            ret = "";
            break;
    }
    return ret;
}

static const char * file_error_description(enum file_errors error) {
    char * ret;
    switch (error)
    {
        case opening_file:
            ret = "unable to open file";
            break;
        case reading_file:
            ret = "unable to read file";
            break;
        case writing_file:
            ret = "unable to write file";
            break;
        case closing_file:
            ret = "unable to close file";
            break;
        case memory_heap:
            ret = "not enough memory heap";
            break;
        case wrong_arg:
            ret = "wrong argument/s";
            break;
        default:
            ret = "";
            break;
    }
    return ret;
}