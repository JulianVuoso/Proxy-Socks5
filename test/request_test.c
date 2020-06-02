#include <stdio.h>
#include <stdlib.h>
#include <check.h>

#include "request.h"
#include "tests.h"

START_TEST (test_request_normal_ipv4) {
    request_parser parser;
    request_parser_init(&parser);
    uint8_t data[] = {
        0x05, 0x01, 0x00, 0x01, 
        0x36, 0xcf, 0x21, 0xa7, 
        0x00, 0x50,
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum request_state state = request_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(request_done, state);
    ck_assert_uint_eq(address_ipv4, parser.dest->address_type);
    // Cuando tenga netutils, verificar IP + Puerto
    // Agregar un metodo en request que me complete un struct sockaddr *
    request_parser_close(&parser);
}
END_TEST

START_TEST (test_request_normal_ipv6) {
    request_parser parser;
    request_parser_init(&parser);
    uint8_t data[] = {
        0x05, 0x01, 0x00, 0x04, 
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x50,
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum request_state state = request_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(request_done, state);
    ck_assert_uint_eq(address_ipv6, parser.dest->address_type);
    // Cuando tenga netutils, verificar IP + Puerto
    // Agregar un metodo en request que me complete un struct sockaddr *
    request_parser_close(&parser);
}
END_TEST

START_TEST (test_request_normal_fqdn) {
    request_parser parser;
    request_parser_init(&parser);
    uint8_t data[] = {
        0x05, 0x01, 0x00, 0x03, 
        0x0A, 0x67, 0x6F, 0x6F,
        0x67, 0x6C, 0x65, 0x2E,
        0x63, 0x6F, 0x60, 
        0x00, 0x50,
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum request_state state = request_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(request_done, state);
    ck_assert_uint_eq(address_fqdn, parser.dest->address_type);
    // Cuando tenga netutils, verificar IP + Puerto
    // Agregar un metodo en request que me complete un struct sockaddr *
    request_parser_close(&parser);
}
END_TEST

START_TEST (test_request_multiple_request) {
    request_parser parser;
    request_parser_init(&parser);
    uint8_t data[] = {
        0x05, 0x01, 0x00, 0x01, 
        0x36, 0xcf, 0x21, 0xa7, 
        0x00, 0x50,
        0x05, 0x01, 0x00, 0x04, 
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x50,
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum request_state state = request_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(request_done, state);
    ck_assert_uint_eq(address_ipv4, parser.dest->address_type);
    // Cuando tenga netutils, verificar IP + Puerto
    // Agregar un metodo en request que me complete un struct sockaddr *

    errored = false;
    request_parser_init(&parser);
    state = request_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(request_done, state);
    ck_assert_uint_eq(address_ipv6, parser.dest->address_type);
    // Cuando tenga netutils, verificar IP + Puerto
    // Agregar un metodo en request que me complete un struct sockaddr *
    request_parser_close(&parser);
}
END_TEST

START_TEST (test_request_unsupported_version) {
    request_parser parser;
    request_parser_init(&parser);
    uint8_t data[] = {
        0x04, 0x01, 0x00, 0x01, 
        0x36, 0xcf, 0x21, 0xa7, 
        0x00, 0x50,
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum request_state state = request_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(request_error, state);
    ck_assert_uint_eq(error_request_unsupported_version, parser.error);
    request_parser_close(&parser);
}
END_TEST

START_TEST (test_request_unsupported_command) {
    request_parser parser;
    request_parser_init(&parser);
    uint8_t data[] = {
        0x05, 0x03, 0x00, 0x01, 
        0x36, 0xcf, 0x21, 0xa7, 
        0x00, 0x50,
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum request_state state = request_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(request_error, state);
    ck_assert_uint_eq(error_request_unsupported_command, parser.error);
    request_parser_close(&parser);
}
END_TEST

START_TEST (test_request_invalid_reserved_byte) {
    request_parser parser;
    request_parser_init(&parser);
    uint8_t data[] = {
        0x05, 0x01, 0x45, 0x01, 
        0x36, 0xcf, 0x21, 0xa7, 
        0x00, 0x50,
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum request_state state = request_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(request_error, state);
    ck_assert_uint_eq(error_request_invalid_reserved_byte, parser.error);
    request_parser_close(&parser);
}
END_TEST

START_TEST (test_request_invalid_address_type) {
    request_parser parser;
    request_parser_init(&parser);
    uint8_t data[] = {
        0x05, 0x01, 0x00, 0x00, 
        0x36, 0xcf, 0x21, 0xa7, 
        0x00, 0x50,
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum request_state state = request_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(request_error, state);
    ck_assert_uint_eq(error_request_invalid_address_type, parser.error);
    request_parser_close(&parser);
}
END_TEST

START_TEST (test_request_invalid_fqdn_length) {
    request_parser parser;
    request_parser_init(&parser);
    uint8_t data[] = {
        0x05, 0x01, 0x00, 0x03, 
        0x00, 0xcf, 0x21, 0xa7, 
        0x00, 0x50,
    };
    buffer b; FIXBUF(b, data);
    bool errored = false;
    enum request_state state = request_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(request_error, state);
    ck_assert_uint_eq(error_request_invalid_fqdn_length, parser.error);
    request_parser_close(&parser);
}
END_TEST

Suite * 
request_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("socks");

    /* Core test case */
    tc = tcase_create("request");

    tcase_add_test(tc, test_request_normal_ipv4);
    tcase_add_test(tc, test_request_normal_ipv6);
    tcase_add_test(tc, test_request_normal_fqdn);
    tcase_add_test(tc, test_request_multiple_request);
    
    tcase_add_test(tc, test_request_unsupported_version);
    tcase_add_test(tc, test_request_unsupported_command);
    tcase_add_test(tc, test_request_invalid_reserved_byte);
    tcase_add_test(tc, test_request_invalid_address_type);
    tcase_add_test(tc, test_request_invalid_fqdn_length);
    
    suite_add_tcase(s, tc);

    return s;
}

int 
main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = request_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}