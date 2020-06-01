# Compilation flags
CC = gcc
CFLAGS = -DHAVE_CONFIG_H -pthread -g --std=c11 -pedantic \
	-pedantic-errors -Wall -Wextra  \
	-Wno-unused-parameter -Wno-implicit-fallthrough \
	-D_POSIX_C_SOURCE=200112L

SOURCES=$(wildcard src/*.c)
TESTS=$(wildcard test/*.c)
OBJECTS=$(SOURCES:.c=.o)
#TEST_OBJECTS=$(TESTS:.c=.o)
LIBRARY = ./include
TEST_LIB = -lcheck -lsubunit -lrt -lm