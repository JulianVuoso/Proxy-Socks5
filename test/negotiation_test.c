#include <stdio.h>
#include <stdlib.h>
#include <check.h>

#include "negotiation.h"
#include "tests.h"

#define FIXBUF(b, data) buffer_init(&(b), N(data), (data)); \
                        buffer_write_adv(&(b), N(data))

START_TEST (test_negot_user_and_pwd) {
    negot_parser parser;
    negot_parser_init(&parser);
    uint8_t data[] = {
        0x01, 
        2, 'j', 'v', 
        3, '0', '1', '2'
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    enum negot_state state = negot_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(negot_done, state);
    ck_assert_str_eq("jv", (char*)parser.username->uname);
    ck_assert_str_eq("012", (char*)parser.password->passwd);

    negot_parser_close(&parser);
}
END_TEST

START_TEST (test_negot_unsupported_version) {
    negot_parser parser;
    negot_parser_init(&parser);
    uint8_t data[] = {
        0x05, 
        0x01, 0x00,
        0x01, 0x36,
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    enum negot_state state = negot_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(negot_error, state);
    ck_assert_uint_eq(error_negot_unsupported_version, parser.error);
    
    negot_parser_close(&parser);
}
END_TEST

START_TEST (test_negot_empty_user) {
    negot_parser parser;
    negot_parser_init(&parser);
    uint8_t data[] = {
        0x01, 
        0x00,
        0x01,0x04
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    enum negot_state state = negot_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(negot_error, state);
    ck_assert_uint_eq(error_negot_invalid_ulen, parser.error);
    
    negot_parser_close(&parser);
}
END_TEST

START_TEST (test_negot_empty_pwd) {
    negot_parser parser;
    negot_parser_init(&parser);
    uint8_t data[] = {
        0x01, 
        0x01,0x01,
        0x00
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    enum negot_state state = negot_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(negot_error, state);
    ck_assert_uint_eq(error_negot_invalid_plen, parser.error);
    
    negot_parser_close(&parser);
}
END_TEST

Suite * 
negot_suite(void) {
    Suite *s;
    TCase *tc;
    s = suite_create("socks");

    /* Core test case */
    tc = tcase_create("negotiation");
    tcase_add_test(tc, test_negot_user_and_pwd);
    tcase_add_test(tc, test_negot_unsupported_version);
    tcase_add_test(tc, test_negot_empty_user);
    tcase_add_test(tc, test_negot_empty_pwd);
    suite_add_tcase(s, tc);

    return s;
}

int 
main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = negot_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}