#include <stdio.h>
#include <stdlib.h>
#include <check.h>

#include "ettercap.h"
#include "tests.h"

#define FIXBUF(b, data) buffer_init(&(b), N(data), (data)); \
                        buffer_write_adv(&(b), N(data))
