#include <stdlib.h>
#include <check.h>

#include "tests.h"
#include "dohclient.h"


START_TEST (test_dohclient_normal) {
}
END_TEST

Suite *dohclient_suite(void){
    Suite *s;
    TCase *tc;

    s = suite_create("socks");

    /* Core test case */
    tc = tcase_create("dohClient");

    tcase_add_test(tc, test_dohclient_normal);
    suite_add_tcase(s, tc);

    return s;
}

int main(){
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = dohclient_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}