# Compilation flags
CC = gcc
CFLAGS = -pthread -g --std=c11 -pedantic -pedantic-errors \
	-Wall -Wextra -Wno-unused-parameter -Wno-implicit-fallthrough \
	-D_POSIX_C_SOURCE=200112L

SOURCES=$(wildcard src/*.c)
TESTS=$(wildcard test/*.c)
OBJECTS=$(SOURCES:.c=.o)
TEST_OBJECTS=$(TESTS:.c=.o)
LIBRARY = ./include
SRC_FOLDER = ./src # Added .c as libraries for testing
TEST_LIB_FLAGS = -lcheck -lsubunit -lrt -lm