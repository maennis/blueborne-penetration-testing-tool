#include <check.h>
#include <stdlib.h>
#include <syslog.h>
#include "../src/logger.h"
#include "../src/bluetooth.h"

#define INVALID_DEV_ID  -1
#define TEST_SUITE_NAME "check_bbptt"

START_TEST(test_logger_run)
{
    logger_init(TEST_SUITE_NAME);
    systemlog(LOG_AUTH | LOG_INFO, "%s test suite started", TEST_SUITE_NAME);
    logger_close();
}
END_TEST

// bluetooth.h tests
START_TEST(test_open_bluetooth_device_invalid_id)
{
    int hci_socket = open_bluetooth_device(INVALID_DEV_ID);
    ck_assert_int_lt(hci_socket, 0);
}
END_TEST

START_TEST(test_open_bluetooth_device_valid_id)
{
    int hci_socket, device_id;
    device_id = get_bluetooth_device_id();
    ck_assert_msg(device_id >= 0, "Invalid bluetooth device ID. A bluetooth adapter may not be available.");
    hci_socket = open_bluetooth_device(device_id);
    ck_assert_int_ge(hci_socket, 0);
}
END_TEST

Suite * bbptt_suite(void)
{
    Suite *s;
    TCase *tc_setup, *tc_bluetooth_open_device_invalid_id, *tc_bluetooth_open_device_valid_id;
    s = suite_create("BBPTT");

    // Set up
    tc_setup = tcase_create("Setup");
    // Bluetooth
    tc_bluetooth_open_device_invalid_id = tcase_create("open_bluetooth_device invalid id");
    tc_bluetooth_open_device_valid_id = tcase_create("open_bluetooth_device invalid id");

    tcase_add_test(tc_setup, test_logger_run);
    suite_add_tcase(s, tc_setup);
    tcase_add_test(tc_bluetooth_open_device_invalid_id, test_open_bluetooth_device_invalid_id);
    suite_add_tcase(s, tc_bluetooth_open_device_invalid_id);
    tcase_add_test(tc_bluetooth_open_device_valid_id, test_open_bluetooth_device_valid_id);
    suite_add_tcase(s, tc_bluetooth_open_device_valid_id);
    
    return s;
}

int main(void)
{
    int num_tests_failed;
    Suite *s;
    SRunner *sr;
    
    s = bbptt_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    num_tests_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return num_tests_failed;
}
