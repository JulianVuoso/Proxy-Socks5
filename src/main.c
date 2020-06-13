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
#include <arpa/inet.h>

#include "selector.h"
#include "socks5.h"

#define IPV4_ADDRESS    INADDR_ANY
#define IPV6_ADDRESS    "::"

enum socket_errors { socket_no_error, error_socket_create, error_socket_bind, error_socket_listen, error_invalid_address};

static unsigned create_socket_ipv4(uint32_t address, unsigned port, int * server_fd);
static unsigned create_socket_ipv6(const char * address, unsigned port, int * server_fd);
static const char * socket_error_description(enum socket_errors error);

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int
main(const int argc, const char **argv) {
    unsigned port = 1080;

    if(argc == 1) {
        // utilizamos el default
    } else if(argc == 2) {
        char *end     = 0;
        const long sl = strtol(argv[1], &end, 10);

        if (end == argv[1]|| '\0' != *end 
           || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
           || sl < 0 || sl > USHRT_MAX) {
            fprintf(stderr, "port should be an integer: %s\n", argv[1]);
            return 1;
        }
        port = sl;
    } else {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    // no tenemos nada que leer de stdin
    close(0);

    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;

    const char * err_msg = NULL;
    int server_ipv4, server_ipv6;
    
    enum socket_errors error_ipv4 = create_socket_ipv4(IPV4_ADDRESS, port, &server_ipv4);
    if (error_ipv4 != socket_no_error) {
        err_msg = socket_error_description(error_ipv4);
        goto finally;
    }
    enum socket_errors error_ipv6 = create_socket_ipv6(IPV6_ADDRESS, port, &server_ipv6);
    if (error_ipv6 != socket_no_error) {
        err_msg = socket_error_description(error_ipv6);
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %u\n", port);

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    if(selector_fd_set_nio(server_ipv4) == -1 || 
        selector_fd_set_nio(server_ipv6) == -1) {
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
    const struct fd_handler socks5 = {
        .handle_read       = socks5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    ss = selector_register(selector, server_ipv4, &socks5,
                                              OP_READ, NULL);
    if (ss == SELECTOR_SUCCESS) {
        ss = selector_register(selector, server_ipv6, &socks5,
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
    return ret;
}

static unsigned 
create_socket_ipv4(uint32_t address, unsigned port, int * server_fd) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(address);
    addr.sin_port        = htons(port);

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
    setsockopt(*server_fd, SOL_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int));

    if(bind(*server_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        return error_socket_bind;
    }

    if (listen(*server_fd, 20) < 0) {
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
        default:
            ret = "";
            break;
    }
    return ret;
}