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
#include <time.h>        // timeout type

#include "selector.h"
#include "socks5.h"
#include "admin_socks5.h"
#include "users.h"
#include "logger.h"
#include "args.h"
#include "doh_server_struct.h"
#include "config.h"

#define USERS_FILENAME  "users.txt"

#define LOGGER_FD       1
#define LOGGER_LEVEL    DEBUG

enum socket_errors { socket_no_error, error_socket_create, error_socket_bind, error_socket_listen, error_invalid_address, error_socket_sockopt};
enum socket_options { socket_server_ipv4, socket_server_ipv6, socket_admin_ipv4, socket_admin_ipv6 };

static unsigned create_socket_option(enum socket_options option, struct socks5args args, int * fd);
static unsigned create_socket_ipv4(const char *  address, unsigned port, int * server_fd);
static unsigned create_socket_ipv6(const char * address, unsigned port, int * server_fd);
static unsigned create_admin_socket_ipv4(const char * address, unsigned port, int * admin_fd);
static unsigned create_admin_socket_ipv6(const char * address, unsigned port, int * admin_fd);
static const char * socket_error_description(enum socket_errors error);
static const char * file_error_description(enum file_errors error);

static bool done = false;
static time_t timeout_gen = INIT_GEN_TIMEOUT, timeout_con = INIT_CON_TIMEOUT;

static void
sigterm_handler(const int signal) {
    fprintf(stderr, "signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int
main(const int argc, const char **argv) {

    /* Try to read users file */
    enum file_errors file_state = read_users_file(USERS_FILENAME);
    if(file_state != file_no_error){
        fprintf(stderr, "Users file read failed. Issue: %s\n", file_error_description(file_state));
    }

    /* Parse args */
    struct socks5args args;
    parse_args(argc, argv, &args);
    set_doh_info(args.doh);
    
    const char * err_msg = NULL;

    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;

    int server_ipv4 = -1, server_ipv6 = -1, admin_ipv4 = -1, admin_ipv6 = -1;
    
    int * aux_fd[4] = {&server_ipv4, &server_ipv6, &admin_ipv4, &admin_ipv6};
    char * aux_addr[4] = {args.socks_addr_ipv4, args.socks_addr_ipv6, args.mng_addr_ipv4, args.mng_addr_ipv6};
    for (enum socket_options op = socket_server_ipv4; op <= socket_admin_ipv6; op++) {
        if (aux_addr[op] != NULL) {
            enum socket_errors err_sock = create_socket_option(op, args, aux_fd[op]);
            if (err_sock != socket_no_error) {
                err_msg = socket_error_description(err_sock);
                goto finally;
            }
            if (selector_fd_set_nio(*aux_fd[op]) == -1) {
                err_msg = "getting server socket flags";
                goto finally;
            }
        }
    }

    fprintf(stderr, "Listening on TCP port %u\n", args.socks_port);

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 1,
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
    enum logger_level level = ACCESS_LOG;
    if (args.disectors_enabled) level = PASS_LOG; 
    ss = logger_init(LOGGER_FD, level, selector);


    const struct fd_handler socks5 = {
        .handle_read       = socks5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    if (server_ipv4 != -1 && ss == SELECTOR_SUCCESS) {
        ss = selector_register(selector, server_ipv4, &socks5,
                                              OP_READ, NULL, NO_TIMEOUT);
    }
    if (server_ipv6 != -1 && ss == SELECTOR_SUCCESS) {
        ss = selector_register(selector, server_ipv6, &socks5,
                                              OP_READ, NULL, NO_TIMEOUT);
    }
    const struct fd_handler admin_handlers = {
        .handle_read       = admin_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    if (admin_ipv4 != -1 && ss == SELECTOR_SUCCESS) {
        ss = selector_register(selector, admin_ipv4, &admin_handlers,
                                              OP_READ, NULL, NO_TIMEOUT);
    }
    if (admin_ipv6 != -1 && ss == SELECTOR_SUCCESS) {
        ss = selector_register(selector, admin_ipv6, &admin_handlers,
                                              OP_READ, NULL, NO_TIMEOUT);
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
        selector_check_timeout(selector, timeout_gen, timeout_con);
    }

    file_state = update_users_file(USERS_FILENAME);
    if(file_state != file_no_error){
        fprintf(stderr, "Users file updating failed. Error: %s\n", file_error_description(file_state));
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
        fprintf(stderr, "Closing proxy ipv4 sock...\n");
        close(server_ipv4);
    }
    if(server_ipv6 >= 0) {
        fprintf(stderr, "Closing proxy ipv6 sock...\n");
        close(server_ipv6);
    }
    if(admin_ipv4 >= 0) {
        fprintf(stderr, "Closing admin ipv4 sock...\n");
        close(admin_ipv4);
    }
    if(admin_ipv6 >= 0) {
        fprintf(stderr, "Closing admin ipv6 sock...\n");
        close(admin_ipv6);
    }

    free_users_list();
    
    return ret;
}

static unsigned create_socket_option(enum socket_options option, struct socks5args args, int * fd) {
    switch (option)
    {
        case socket_server_ipv4:
            return create_socket_ipv4(args.socks_addr_ipv4, args.socks_port, fd);            
        case socket_server_ipv6:
            return create_socket_ipv6(args.socks_addr_ipv6, args.socks_port, fd);
        case socket_admin_ipv4:
            return create_admin_socket_ipv4(args.mng_addr_ipv4, args.mng_port, fd);
        case socket_admin_ipv6:
            return create_admin_socket_ipv6(args.mng_addr_ipv6, args.mng_port, fd);
        default:
            abort();
            break;
    }
}

static unsigned bind_and_listen(int fd, struct sockaddr * addr, socklen_t length) {
    if(bind(fd, addr, length) < 0) {
        return error_socket_bind;
    }

    if (listen(fd, 20) < 0) {
        return error_socket_listen;
    }

    return socket_no_error;
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

    return bind_and_listen(*server_fd, (struct sockaddr*) &addr, sizeof(addr));
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

    return bind_and_listen(*server_fd, (struct sockaddr*) &addr, sizeof(addr));
}

static unsigned
create_admin_socket_ipv4(const char * address, unsigned port, int * admin_fd) {
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
    setsockopt(*admin_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    struct sctp_initmsg initmsg;
    memset(&initmsg, 0, sizeof(initmsg));
    initmsg.sinit_num_ostreams = 1;
    initmsg.sinit_max_instreams = 1;
    initmsg.sinit_max_attempts = 4;
    if (setsockopt(*admin_fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) < 0) {
        return error_socket_sockopt;
    }
    
    return bind_and_listen(*admin_fd, (struct sockaddr*) &addr, sizeof(addr));
}

static unsigned 
create_admin_socket_ipv6(const char * address, unsigned port, int * admin_fd) {
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family      = AF_INET6;
    addr.sin6_port        = htons(port);
    if (inet_pton(AF_INET6, address, &addr.sin6_addr) == 0) {
        return error_invalid_address;
    }
    
    *admin_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);
    if (*admin_fd < 0) {
        return error_socket_create;
    }
    // man 7 ip. no importa reportar nada si falla.
    setsockopt(*admin_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
    if (setsockopt(*admin_fd, SOL_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int)) < 0) {
        return error_socket_sockopt;
    }
    struct sctp_initmsg initmsg;
    memset(&initmsg, 0, sizeof(initmsg));
    initmsg.sinit_num_ostreams = 1;
    initmsg.sinit_max_instreams = 1;
    initmsg.sinit_max_attempts = 4;
    if (setsockopt(*admin_fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) < 0) {
        return error_socket_sockopt;
    }

    return bind_and_listen(*admin_fd, (struct sockaddr*) &addr, sizeof(addr));
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
        case max_users_reached:
            ret = "there is no more place for users";
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

/* Config getters and setters */
time_t get_timeout_gen() {
    return timeout_gen;
}

void set_timeout_gen(time_t time) {
    timeout_gen = time;
}

time_t get_timeout_con() {
    return timeout_con;
}

void set_timeout_con(time_t time) {
    timeout_con = time;
}