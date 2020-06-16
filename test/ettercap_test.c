#include <stdio.h>
#include <stdlib.h>
#include <check.h>

#include "ettercap.h"
#include "tests.h"

#define FIXBUF(b, data) buffer_init(&(b), N(data), (data)); \
                        buffer_write_adv(&(b), N(data))

START_TEST (test_ettercap_http_valid) {
    ettercap_parser parser;
    ettercap_parser_init(&parser, HTTP_PORT);
    uint8_t  data[] = "GET /path HTTP/1.1\r\nHost: thisisatest.com.ar\r\nAuthorization: Basic YWxndW51c3VhcmlvOmFsZ3VuYXBhc3N3b3Jk\r\nX-header: X-value\r\n\r\n";
    buffer b;
    FIXBUF(b, data);
    bool errored = false;
    ettercap_state state = ettercap_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(ettercap_done, state);
    // ck_assert_str_eq("algunusuario", (char*) parser.username);
    // ck_assert_str_eq("algunapassword", (char*) parser.password);

    ck_assert_str_eq("algunusuario:algunapassword", (char*) parser.username);

    ettercap_parser_close(&parser);
}
END_TEST


Suite * 
negot_suite(void) {
    Suite *s;
    TCase *tc;
    s = suite_create("socks");

    /* Core test case */
    tc = tcase_create("ettercap");
    tcase_add_test(tc, test_ettercap_http_valid); // TODO add each test

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