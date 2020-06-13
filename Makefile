.PHONY=clean all
include Makefile.inc
EXEC = run
EXEC_TESTS = test

# all: $(EXEC_TESTS)
# all: buffer parser parser_utils hello request negotiation selector stm 
all: buffer_test parser_test parser_utils_test hello_test request_test negotiation_test stm_test \
	run
# selector_test
# compile: $(SOURCES)
# 	$(CC) $(CFLAGS) -I$(LIBRARY) -c $(SOURCES) -o $(OBJECTS)

# tests: $(TEST_OBJECTS)
#	$(CC) $(CFLAGS) -I$(LIBRARY) $(TEST_OBJECTS) -o $(CLIENT)
# $(EXEC_TESTS): $(OBJECTS) $(TEST_OBJECTS)
# 	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS) $(TEST_OBJECTS) $< -o test/$@.out $(TEST_LIB_FLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o $@

# parser: src/parser.c
# 	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/parser.o

# parser_utils: src/parser_utils.c
# 	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/parser_utils.o

# buffer: src/buffer.c
# 	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/buffer.o

# hello: src/hello.c
# 	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/hello.o

# request: src/request.c
# 	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/request.o

# negotiation: src/negotiation.c
# 	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/negotiation.o

# selector: src/selector.c
# 	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/selector.o

# stm: src/stm.c
# 	$(CC) $(CFLAGS) -I$(LIBRARY) -c $< -o src/stm.o

run: $(OBJECTS)
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS) -o src/$@.out

parser_test: $(OBJECTS_NO_MAIN) $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS_NO_MAIN) test/$@.o -o test/$@.out $(TEST_LIB_FLAGS)

parser_utils_test: $(OBJECTS_NO_MAIN) $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS_NO_MAIN) test/$@.o -o test/$@.out $(TEST_LIB_FLAGS)

buffer_test: $(OBJECTS_NO_MAIN) $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS_NO_MAIN) test/$@.o -o test/$@.out $(TEST_LIB_FLAGS)

hello_test: $(OBJECTS_NO_MAIN) $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS_NO_MAIN) test/$@.o -o test/$@.out $(TEST_LIB_FLAGS)

request_test: $(OBJECTS_NO_MAIN) $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS_NO_MAIN) test/$@.o -o test/$@.out $(TEST_LIB_FLAGS)

negotiation_test: $(OBJECTS_NO_MAIN) $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS_NO_MAIN) test/$@.o -o test/$@.out $(TEST_LIB_FLAGS)

# selector_test: $(OBJECTS_NO_MAIN) $(TEST_OBJECTS)
# 	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS_NO_MAIN) test/$@.o -o test/$@.out $(TEST_LIB_FLAGS)

stm_test: $(OBJECTS_NO_MAIN) $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -I$(LIBRARY) $(OBJECTS_NO_MAIN) test/$@.o -o test/$@.out $(TEST_LIB_FLAGS)

# clean:
# 	rm -rf src/*.o src/*.out test/*.o test/*.out \
# 	parser_test parser_utils_test buffer_test hello_test request_test negotiation_test \
# 	selector_test stm_test

clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS) src/*.out test/*.out