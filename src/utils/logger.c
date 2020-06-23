#include <stdio.h>
#include <stdarg.h>
#include "logger.h"

#define LOGGER_BUF_SIZE     2048

// Retorna la cantidad de elementos de un arreglo
#define N(x) (sizeof(x)/sizeof(x[0]))

struct logger {
    enum logger_level level;
    int logger_fd;

    uint8_t buffer_mem[LOGGER_BUF_SIZE];
    buffer logger_buf;
    fd_selector selector;
};

static struct logger log;

static void logger_write(struct selector_key * key);

static const fd_handler logger_handler = {
    .handle_read = NULL,
    .handle_write = logger_write,
    .handle_block = NULL,
    .handle_close = NULL,
};

selector_status logger_init(int logger_fd, enum logger_level level, fd_selector selector) {
    log.level = level;
    log.logger_fd = logger_fd;

    buffer_init(&log.logger_buf, N(log.buffer_mem), log.buffer_mem);
    log.selector = selector;
    return selector_register(selector, logger_fd, &logger_handler, OP_NOOP, NULL, NO_TIMEOUT);
}

void logger_log(enum logger_level level, char * format, ...) {
    /* Si el logger esta en ERROR (fd < 0) o el nivel pedido es menor al del logger */
    if (log.logger_fd < 0 || !(log.level <= level)) {
        return;
    }
    
    size_t nbytes;
    uint8_t * buf_write_ptr = buffer_write_ptr(&log.logger_buf, &nbytes);
    va_list format_args;
    va_start(format_args, format);
    int n = vsnprintf((char *) buf_write_ptr, nbytes, format, format_args);
    va_end(format_args);
    if (n < 0) {
        log.logger_fd = -1;
        return;
    }
    unsigned u_n = (unsigned) n; // n >= 0
    buffer_write_adv(&log.logger_buf, (u_n < nbytes) ? u_n + 1 : nbytes);

    if (buffer_can_read(&log.logger_buf)) {
        selector_set_interest(log.selector, log.logger_fd, OP_WRITE);
    }
}

static void logger_write(struct selector_key * key) {
    if (log.logger_fd < 0) {
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    size_t nbytes;
    uint8_t * buf_read_ptr = buffer_read_ptr(&log.logger_buf, &nbytes);
    ssize_t n = write(key->fd, buf_read_ptr, nbytes);
    if (n <= 0) {
        log.logger_fd = -1;
        selector_unregister_fd(key->s, key->fd);
        return;
    }
    buffer_read_adv(&log.logger_buf, n);
    if (!buffer_can_read(&log.logger_buf)) {
        selector_set_interest_key(key, OP_NOOP);
    }
}