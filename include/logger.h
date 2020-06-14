#ifndef LOGGER_H_2d22644fb43dc8c38ca17ff09af186792c30e7b7
#define LOGGER_H_2d22644fb43dc8c38ca17ff09af186792c30e7b7

#include <stdint.h>
#include "buffer.h"
#include "selector.h"

enum logger_level { DEBUG = 0, PROD};

void logger_init(int logger_fd, enum logger_level level, fd_selector s);

void logger_log(enum logger_level level, char * format, ...);

#endif