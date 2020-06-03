.PHONY=clean all
include Makefile.inc

all: buffer parser parser_utils hello negotiation \
buffer_test parser_test parser_utils_test hello_test negotiation_test

# compile: $(SOURCES)
# 	$(CC) $(CFLAGS) -I$(LIBRARY) -c $(SOURCES) -o $(OBJECTS)

# tests: $(TEST_OBJECTS)
#	$(CC) $(CFLAGS) -I$(LIBRARY) $(TEST_OBJECTS) -o $(CLIENT)
%.o: %.c
	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o $@

parser: src/parser.c
	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/parser.o

parser_utils: src/parser_utils.c
	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/parser_utils.o

buffer: src/buffer.c
	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/buffer.o

hello: src/hello.c
	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/hello.o

negotiation: src/negotiation.c
	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/negotiation.o

parser_test: test/parser_test.o
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS) $< -o test/parser_test.out $(TEST_LIB)

parser_utils_test: test/parser_utils_test.o
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS) $< -o test/parser_utils_test.out $(TEST_LIB)

buffer_test: test/buffer_test.o
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS) $< -o test/buffer_test.out $(TEST_LIB)

hello_test: test/hello_test.o
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS) $< -o test/hello_test.out $(TEST_LIB)

negotiation_test: test/negotiation_test.o
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS) $< -o test/negotiation_test.out $(TEST_LIB)

clean:
	rm -rf src/*.o src/*.out test/*.o test/*.out \
	parser_test parser_utils_test buffer_test hello_test negotiation_test