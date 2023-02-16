#include <check.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include "../src/logger.h"
#include "../src/bluetooth.h"
#include "../src/utils.h"

#define TEST_SUITE_NAME         "check_bbptt"

#define INVALID_DEV_ID           -1

#define MADE_UP_ALLOWLIST_FILE  "madeupfile"
#define VALID_ALLOWLIST_FILE    "res/allowlist.txt"
#define VALID_ALLOWLIST_FILE_2  "res/allowlist-2.txt"

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

// allowlist tests
START_TEST(test_load_missing_allowlist)
{
    int num_addresses = load_allowlist(MADE_UP_ALLOWLIST_FILE, NULL);
    ck_assert_int_lt(num_addresses, 0);
}
END_TEST

START_TEST(test_load_allowlist)
{
    int num_addresses, expected_addresses = 2;
    char **allowed_addresses;
    allowed_addresses =  (char **) malloc(sizeof(char *) * expected_addresses);
    for (int i = 0; i < expected_addresses; i++)
        allowed_addresses[i] = (char *) malloc(sizeof(char) * BLUETOOTHADDRESSLEN);
    num_addresses = load_allowlist(VALID_ALLOWLIST_FILE, allowed_addresses);
    for (int i = 0; i < expected_addresses; i++)
        free(allowed_addresses[i]);
    free(allowed_addresses);
    ck_assert_int_eq(num_addresses, expected_addresses); 
}
END_TEST

START_TEST(test_load_allowlist_2)
{
    int num_addresses, expected_addresses = 5;
    char **allowed_addresses;
    allowed_addresses =  (char **) malloc(sizeof(char *) * expected_addresses);
    for (int i = 0; i < expected_addresses; i++)
        allowed_addresses[i] = (char *) malloc(sizeof(char) * BLUETOOTHADDRESSLEN);
    num_addresses = load_allowlist(VALID_ALLOWLIST_FILE_2, allowed_addresses);
    for (int i = 0; i < expected_addresses; i++)
        free(allowed_addresses[i]);
    free(allowed_addresses);
    ck_assert_int_eq(num_addresses, expected_addresses); 
}
END_TEST

START_TEST(test_validate_valid_allowlist)
{
    int is_valid, num_addresses = 3;
    char **allowed_addresses;
    allowed_addresses =  (char **) malloc(sizeof(char *) * num_addresses);
    for (int i = 0; i < num_addresses; i++)
        allowed_addresses[i] = (char *) malloc(sizeof(char) * BLUETOOTHADDRESSLEN);
    strcpy(allowed_addresses[0], "00:17:06:EA:2D:1D");
    strcpy(allowed_addresses[1], "00:17:06:EA:2D:10");
    strcpy(allowed_addresses[2], "84:C5:A6:53:9A:C0");

    is_valid = validate_allowlist(allowed_addresses, num_addresses);
    for (int i = 0; i < num_addresses; i++)
        free(allowed_addresses[i]);
    free(allowed_addresses);
    ck_assert_int_eq(is_valid, 1);
}
END_TEST

START_TEST(test_validate_invalid_allowlist)
{
    int is_valid, num_addresses = 3;
    char **allowed_addresses;
    allowed_addresses =  (char **) malloc(sizeof(char *) * num_addresses);
    for (int i = 0; i < num_addresses; i++)
        allowed_addresses[i] = (char *) malloc(sizeof(char) * BLUETOOTHADDRESSLEN);
    strcpy(allowed_addresses[0], "00:17:06:EA:2D:1D");
    strcpy(allowed_addresses[1], "invalidaddress");
    strcpy(allowed_addresses[2], "84:C5:A6:53:9A:C0");

    is_valid = validate_allowlist(allowed_addresses, num_addresses);
    for (int i = 0; i < num_addresses; i++)
        free(allowed_addresses[i]);
    free(allowed_addresses);
    ck_assert_int_eq(is_valid, 0);
}
END_TEST

START_TEST(test_is_in_allowlist)
{
    int in_allowlist, num_addresses = 3;
    char **allowed_addresses;
    char* address = "00:17:06:EA:2D:10";
    allowed_addresses =  (char **) malloc(sizeof(char *) * num_addresses);
    for (int i = 0; i < num_addresses; i++)
        allowed_addresses[i] = (char *) malloc(sizeof(char) * BLUETOOTHADDRESSLEN);
    strcpy(allowed_addresses[0], "00:17:06:EA:2D:1D");
    strcpy(allowed_addresses[1], "00:17:06:EA:2D:10");
    strcpy(allowed_addresses[2], "84:C5:A6:53:9A:C0");

    in_allowlist = is_in_allowlist(address, allowed_addresses, num_addresses);
    for (int i = 0; i < num_addresses; i++)
        free(allowed_addresses[i]);
    free(allowed_addresses);
    ck_assert_int_gt(in_allowlist, 0);
}
END_TEST

START_TEST(test_not_in_allowlist)
{
    int in_allowlist, num_addresses = 3;
    char **allowed_addresses;
    char* address = "11:17:06:EA:2D:10";
    allowed_addresses =  (char **) malloc(sizeof(char *) * num_addresses);
    for (int i = 0; i < num_addresses; i++)
        allowed_addresses[i] = (char *) malloc(sizeof(char) * BLUETOOTHADDRESSLEN);
    strcpy(allowed_addresses[0], "00:17:06:EA:2D:1D");
    strcpy(allowed_addresses[1], "00:17:06:EA:2D:10");
    strcpy(allowed_addresses[2], "84:C5:A6:53:9A:C0");

    in_allowlist = is_in_allowlist(address, allowed_addresses, num_addresses);
    
    for (int i = 0; i < num_addresses; i++)
        free(allowed_addresses[i]);
    free(allowed_addresses);
    ck_assert_int_eq(in_allowlist, 0);
}
END_TEST

START_TEST(test_allowlist_e2e)
{
    int num_addresses, is_valid, in_allowlist, expected_addresses = 2;
    char **allowed_addresses;
    allowed_addresses =  (char **) malloc(sizeof(char *) * expected_addresses);
    for (int i = 0; i < expected_addresses; i++)
        allowed_addresses[i] = (char *) malloc(sizeof(char) * BLUETOOTHADDRESSLEN);
    num_addresses = load_allowlist(VALID_ALLOWLIST_FILE, allowed_addresses);
    ck_assert_int_eq(num_addresses, expected_addresses);
    is_valid = validate_allowlist(allowed_addresses, num_addresses);
    ck_assert_int_eq(is_valid, 1);
    in_allowlist = is_in_allowlist("00:17:06:EA:2D:1D", allowed_addresses, num_addresses);
    ck_assert_int_eq(in_allowlist, 1);
    for (int i = 0; i < expected_addresses; i++)
        free(allowed_addresses[i]);
    free(allowed_addresses);
}
END_TEST

START_TEST(test_create_svc_attr_search_pdu_no_cont)
{
    char *pdu;
    uint8_t cont_len = 0x00, pdu_id = SDP_SVC_SEARCH_ATTR_REQ;
    sdp_pdu_hdr_t *pdu_header;
    size_t len = SDP_PDU_ATTR_PARAM_LEN + sizeof(sdp_pdu_hdr_t);

    pdu = create_sdp_svc_attr_search_pdu(SVC_L2CAP, 0x00, cont_len);
    // Check header values
    pdu_header = (sdp_pdu_hdr_t *) pdu;
    ck_assert_uint_eq(pdu_header->pdu_id, pdu_id);
    ck_assert_uint_eq(pdu_header->plen, htons(SDP_PDU_ATTR_PARAM_LEN));

    // Check the continuation state is set to null
    ck_assert_mem_eq(&(pdu[len - 1]), &cont_len, 1);
}
END_TEST

START_TEST(test_create_svc_attr_search_pdu_cont)
{
    char *pdu, cont_state_s[SDP_BLUEZ_CONT_STATE_LEN + 1];
    uint8_t cont_len = SDP_BLUEZ_CONT_STATE_LEN, pdu_id = SDP_SVC_SEARCH_ATTR_REQ;
    sdp_pdu_hdr_t *pdu_header;
    size_t len = SDP_PDU_ATTR_PARAM_LEN + sizeof(sdp_pdu_hdr_t);
    sdp_cont_state_bluez_t cont_state = { 0 };

    // Create continuation state
    cont_state.timestamp = (uint32_t) time(NULL);
    cont_state.cStateValue.lastIndexSent = 0x1111;
    // Convert continuation state to bytes
    cont_state_to_char(&cont_state, cont_state_s, cont_len);

    pdu = create_sdp_svc_attr_search_pdu(SVC_L2CAP, cont_state_s, cont_len);
    // Check header values
    pdu_header = (sdp_pdu_hdr_t *) pdu;
    ck_assert_uint_eq(pdu_header->pdu_id, pdu_id);
    ck_assert_uint_eq(pdu_header->plen, htons(SDP_PDU_ATTR_PARAM_LEN + cont_len));

    // Check the continuation state matches the string that was created
    ck_assert_mem_eq(&(pdu[len - 1]), cont_state_s, cont_len);
}
END_TEST

Suite * bbptt_suite(void)
{
    Suite *s;
    TCase *tc_setup,
            *tc_bluetooth_open_device_invalid_id,
            *tc_bluetooth_open_device_valid_id,
            *tc_load_missing_allowlist,
            *tc_load_allowlist_1,
            *tc_load_allowlist_2,
            *tc_validate_valid_allowlist,
            *tc_validate_invalid_allowlist,
            *tc_is_in_allowlist,
            *tc_not_in_allowlist,
            *tc_allowlist_e2e,
            *tc_create_svc_attr_search,
            *tc_create_svc_attr_search_cont;
    s = suite_create("BBPTT");

    // Set up
    tc_setup = tcase_create("Setup");
    // Bluetooth
    tc_bluetooth_open_device_invalid_id = tcase_create("open_bluetooth_device invalid id");
    tc_bluetooth_open_device_valid_id = tcase_create("open_bluetooth_device invalid id");
    // Allowlist
    tc_load_missing_allowlist = tcase_create("load_allowlist missing");
    tc_load_allowlist_1 = tcase_create("load_allowlist valid 1");
    tc_load_allowlist_2 = tcase_create("load_allowlist valid 2");
    tc_validate_valid_allowlist = tcase_create("is_valid_allowlist valid");
    tc_validate_invalid_allowlist = tcase_create("is_valid_allowlist invalid");
    tc_is_in_allowlist = tcase_create("is_in_allowlist true");
    tc_not_in_allowlist = tcase_create("is_in_allowlist false");
    tc_allowlist_e2e = tcase_create("allowlist e2e");
    tc_create_svc_attr_search = tcase_create("create sdp svc attr search pdu");
    tc_create_svc_attr_search_cont = tcase_create("create sdp svc attr search cont pdu");

    tcase_add_test(tc_setup, test_logger_run);
    suite_add_tcase(s, tc_setup);
    tcase_add_test(tc_bluetooth_open_device_invalid_id, test_open_bluetooth_device_invalid_id);
    suite_add_tcase(s, tc_bluetooth_open_device_invalid_id);
    tcase_add_test(tc_bluetooth_open_device_valid_id, test_open_bluetooth_device_valid_id);
    suite_add_tcase(s, tc_bluetooth_open_device_valid_id);
    tcase_add_test(tc_load_missing_allowlist, test_load_missing_allowlist);
    suite_add_tcase(s, tc_load_missing_allowlist);
    tcase_add_test(tc_load_allowlist_1, test_load_allowlist);
    suite_add_tcase(s, tc_load_allowlist_1);
    tcase_add_test(tc_load_allowlist_2, test_load_allowlist_2);
    suite_add_tcase(s, tc_load_allowlist_2);
    tcase_add_test(tc_validate_valid_allowlist, test_validate_valid_allowlist);
    suite_add_tcase(s, tc_validate_valid_allowlist);
    tcase_add_test(tc_validate_invalid_allowlist, test_validate_invalid_allowlist);
    suite_add_tcase(s, tc_validate_invalid_allowlist);
    tcase_add_test(tc_is_in_allowlist, test_is_in_allowlist);
    suite_add_tcase(s, tc_is_in_allowlist);
    tcase_add_test(tc_not_in_allowlist, test_not_in_allowlist);
    suite_add_tcase(s, tc_not_in_allowlist);
    tcase_add_test(tc_allowlist_e2e, test_allowlist_e2e);
    suite_add_tcase(s, tc_allowlist_e2e);
    tcase_add_test(tc_create_svc_attr_search, test_create_svc_attr_search_pdu_no_cont);
    suite_add_tcase(s, tc_create_svc_attr_search);
    tcase_add_test(tc_create_svc_attr_search_cont, test_create_svc_attr_search_pdu_cont);
    suite_add_tcase(s, tc_create_svc_attr_search_cont);

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
