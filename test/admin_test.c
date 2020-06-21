#include <stdio.h>
#include <stdlib.h>
#include <check.h>

#include "admin.h"
#include "tests.h"

START_TEST (test_admin_add_user_ok) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x01, 0x00,
        2, 'm', 'b', 
        3, '3', '4', '5'
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(admin_done, state);
    ck_assert_uint_eq(admin_error_none, parser.error);    
    ck_assert_uint_eq(admin_command_add_user, parser.data->command);
    ck_assert_uint_eq(admin_user_type_client, parser.data->option);
    ck_assert_str_eq("mb", (char *) parser.data->value1->value);
    ck_assert_str_eq("345", (char *) parser.data->value2->value);

    admin_parser_close(&parser);
}
END_TEST

START_TEST (test_admin_add_user_inv_utype) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x01, 0x03,
        2, 'm', 'b', 
        3, '3', '4', '5'
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(admin_error, state);
    ck_assert_uint_eq(admin_error_inv_utype, parser.error);  
    ck_assert_uint_eq(admin_command_add_user, parser.data->command);
    ck_assert_uint_eq(0x03, parser.data->option);

    admin_parser_close(&parser);
}
END_TEST

START_TEST (test_admin_add_user_inv_ulen) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x01, 0x00,
        0, 'm', 'b', 
        3, '3', '4', '5'
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(admin_error, state);
    ck_assert_uint_eq(admin_error_inv_ulen, parser.error);  
    ck_assert_uint_eq(admin_command_add_user, parser.data->command);
    ck_assert_uint_eq(admin_user_type_client, parser.data->option);

    admin_parser_close(&parser);
}
END_TEST

START_TEST (test_admin_del_user_ok) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x02, 0, 'm', 'b', 
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(admin_done, state);
    ck_assert_uint_eq(admin_error_none, parser.error);  
    ck_assert_uint_eq(admin_command_del_user, parser.data->command);

    admin_parser_close(&parser);
}
END_TEST

START_TEST (test_admin_del_user_inv_ulen) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x02, 0x00,
        0, 'm', 'b', 
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(admin_done, state);
    ck_assert_uint_eq(admin_error_none, parser.error);  
    ck_assert_uint_eq(admin_command_del_user, parser.data->command);

    admin_parser_close(&parser);
}
END_TEST

START_TEST (test_admin_list_user_ok) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x03 
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(admin_done, state);
    ck_assert_uint_eq(admin_error_none, parser.error);  
    ck_assert_uint_eq(admin_command_list_user, parser.data->command);

    admin_parser_close(&parser);
}
END_TEST

START_TEST (test_admin_get_metric_ok) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x04, 0x01 
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(admin_done, state);
    ck_assert_uint_eq(admin_error_none, parser.error);  
    ck_assert_uint_eq(admin_command_get_metric, parser.data->command);
    ck_assert_uint_eq(admin_metric_conc_conn, parser.data->option);

    admin_parser_close(&parser);
}
END_TEST

START_TEST (test_admin_get_metric_inv_metric) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x04, 0x09 
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(admin_error, state);
    ck_assert_uint_eq(admin_error_inv_metric, parser.error);  
    ck_assert_uint_eq(admin_command_get_metric, parser.data->command);
    ck_assert_uint_eq(0x09, parser.data->option);

    admin_parser_close(&parser);
}
END_TEST

START_TEST (test_admin_get_config_ok) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x05, 0x01 
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(admin_done, state);
    ck_assert_uint_eq(admin_error_none, parser.error);  
    ck_assert_uint_eq(admin_command_get_config, parser.data->command);
    ck_assert_uint_eq(admin_config_buff_read_size, parser.data->option);

    admin_parser_close(&parser);
}
END_TEST

START_TEST (test_admin_get_config_inv_config) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x05, 0x09 
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(admin_error, state);
    ck_assert_uint_eq(admin_error_inv_config, parser.error);  
    ck_assert_uint_eq(admin_command_get_config, parser.data->command);

    admin_parser_close(&parser);
}
END_TEST

START_TEST (test_admin_set_config_ok) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x06, 0x01, 0x01, 0xFF 
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(false, errored);
    ck_assert_uint_eq(admin_done, state);
    ck_assert_uint_eq(admin_error_none, parser.error);  
    ck_assert_uint_eq(admin_command_set_config, parser.data->command);
    ck_assert_uint_eq(admin_config_buff_read_size, parser.data->option);
    ck_assert_uint_eq(0x01, parser.data->value1->length);
    ck_assert_uint_eq(0xFF, parser.data->value1->value[0]);

    admin_parser_close(&parser);
}
END_TEST

START_TEST (test_admin_set_config_inv_config) {
    admin_parser parser;
    admin_parser_init(&parser);
    uint8_t data[] = {
        0x06, 0x09,  
    };
    buffer b; 
    FIXBUF(b, data);
    bool errored = false;
    admin_state state = admin_consume(&b, &parser, &errored);
    ck_assert_uint_eq(true, errored);
    ck_assert_uint_eq(admin_error, state);
    ck_assert_uint_eq(admin_error_inv_config, parser.error);  
    ck_assert_uint_eq(admin_command_set_config, parser.data->command);

    admin_parser_close(&parser);
}
END_TEST



Suite * 
admin_suite(void) {
    Suite *s;
    TCase *tc;
    s = suite_create("socks");

    /* Core test case */
    tc = tcase_create("admin");
    tcase_add_test(tc, test_admin_add_user_ok);
    tcase_add_test(tc, test_admin_add_user_inv_utype);
    tcase_add_test(tc, test_admin_add_user_inv_ulen);
    tcase_add_test(tc, test_admin_del_user_ok);
    tcase_add_test(tc, test_admin_del_user_inv_ulen);
    tcase_add_test(tc, test_admin_list_user_ok);
    tcase_add_test(tc, test_admin_get_metric_ok);
    tcase_add_test(tc, test_admin_get_metric_inv_metric);
    tcase_add_test(tc, test_admin_get_config_ok);
    tcase_add_test(tc, test_admin_get_config_inv_config);
    tcase_add_test(tc, test_admin_set_config_ok);
    tcase_add_test(tc, test_admin_set_config_inv_config);

    suite_add_tcase(s, tc);

    return s;
}

int 
main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = admin_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}