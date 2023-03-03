#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

// Custom Imports
#include "bluetooth.h"
#include "logger.h"
#include "utils.h"

#define MAXFILENAMELEN      255
#define NUM_VULNERABILITIES 3
#define POLL_INTERVAL       30 // In seconds
#define PROGRAM_NAME        "bluebornepentesttool"
#define TRUE                1

_Noreturn void cleanup(int signal);
void print_usage(char * invocation);
void process_device(bdaddr_t *address, int *processed_bt_addresses, char processed_addresses[MAXNUMBTRESP][BLUETOOTHADDRESSLEN], int num_allowlist, char **allowed_addresses);
void set_sigaction(void);
void setup(void);
int setup_allowlist(char **allowed_addresses, char* allowlist_filename);

const cve_check VULNERABILITIES[] = {
    { .name = "CVE-2017-1000250", .check = &is_vulnerable_to_cve_2017_1000250 },
    { .name = "CVE-2017-7085", .check = &is_vulnerable_to_cve_2017_0785 },
    { .name = "CVE-2017-7083 or CVE-2017-8628", .check = &is_vulnerable_to_cve_2017_0783_8628 }
};

int main(int argc, char**argv) {
    struct bluetooth_connection_info bt_info;
    bdaddr_t *bt_address_list, btaddr;
    char processed_bt_addresses[MAXNUMBTRESP][BLUETOOTHADDRESSLEN], **allowed_addresses, allowlist_file[MAXFILENAMELEN] = "allowlist.txt";
    int i, responses, num_allowlist, num_processed_bt_address = 0, opt, poll_int = POLL_INTERVAL;

    while((opt = getopt(argc, argv, "a:p:h")) != -1)
    {
        switch (opt)
        {
            case 'a':
                strcpy(allowlist_file, optarg);
                break;
            case 'p':
                printf("p: %s %d", optarg, atoi(optarg));
                if (!is_number(optarg))
                {
                    perror("Poll value -p must be an integer.\n");
                    print_usage(argv[0]);
                    exit(EXIT_FAILURE);
                }
                poll_int = atoi(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    setup();

    if ((bt_info.device_id = get_bluetooth_device_id()) < 0)
    {
        systemlog(LOG_AUTH | LOG_ERR, "Cannot find bluetooth adapter. Program Exiting");
        fprintf(stderr, "Cannot find bluetooth adapter.  Program Exiting\n");
        exit(EXIT_FAILURE);
    }

    if ((bt_info.hci_socket = open_bluetooth_device(bt_info.device_id)) < 0)
    {
        systemlog(LOG_AUTH | LOG_ERR, "Cannot open HCI socket. Program Exiting");
        fprintf(stderr, "Cannot open HCI socket.  Program Exiting\n");
        exit(EXIT_FAILURE);
    }
    // Allocate memory
    bt_address_list = (bdaddr_t *) malloc(sizeof(bdaddr_t) * MAXNUMBTRESP);
    memset(processed_bt_addresses, 0, MAXNUMBTRESP * BLUETOOTHADDRESSLEN);
    allowed_addresses = (char **) malloc(sizeof(char *) * MAX_ALLOWLIST_SIZE);
    for (i = 0; i < MAX_ALLOWLIST_SIZE; i++)
        allowed_addresses[i] = (char *) malloc(sizeof(char) * BLUETOOTHADDRESSLEN);

    num_allowlist = setup_allowlist(allowed_addresses, allowlist_file);

    while(TRUE)
    {
        systemlog(LOG_AUTH | LOG_INFO, "Begining HCI inquiry");
        responses = make_hci_inquiry(&bt_address_list, &bt_info);
        systemlog(LOG_AUTH | LOG_INFO, "Concluded inquiry.  Found %d devices", responses);
        for (i = 0; i < responses; i++)
        {
            memcpy(&btaddr, bt_address_list + i, sizeof(bdaddr_t));
            process_device(&btaddr, &num_processed_bt_address, processed_bt_addresses, num_allowlist, allowed_addresses);
        }
        systemlog(LOG_AUTH | LOG_INFO, "Finished processing devices", responses);
        sleep(poll_int);
    }

    return 0;
}

_Noreturn void cleanup(int signal)
{
    fprintf(stdout, "Shutting down %s\n", PROGRAM_NAME);
    systemlog(LOG_AUTH | LOG_INFO, "Shutting down %s", PROGRAM_NAME);
    logger_close();
    exit(EXIT_SUCCESS);
}

void print_usage(char *invocation)
{
    printf("Usage: ./s [-h] [-a path] [-p interval]\n");
    printf("    -h      Prints usage.");
    printf("    -a      Pass in the path to an allowlist.  Defaults to allowlist.txt\n");
    printf("    -p      Pass in a poll interval in seconds.  Must be a positive integer.\n");
    printf("            Defaults to 30.\n");
}

void process_device(bdaddr_t *address, int *processed_bt_addresses, char processed_addresses[MAXNUMBTRESP][BLUETOOTHADDRESSLEN], int num_allowlist, char **allowed_addresses)
{
    int i, res, patched = 1;
    char btaddr_s[BLUETOOTHADDRESSLEN] = { 0 };
    ba2str(address, btaddr_s);
    for (i = 0; i < *processed_bt_addresses; i++)
        if (strcmp(btaddr_s, processed_addresses[i]) == 0)
            return;
    strcpy(processed_addresses[*processed_bt_addresses], btaddr_s);
    (*processed_bt_addresses)++;
    if (!is_in_allowlist(btaddr_s, allowed_addresses, num_allowlist))
    {
        systemlog(LOG_AUTH | LOG_INFO, "Device with address %s not in allowlist.  Skipping.", btaddr_s);
        return;
    }
    systemlog(LOG_AUTH | LOG_INFO, "Processing device with address %s.", btaddr_s);
    for (i = 0; i < NUM_VULNERABILITIES; i++)
    {
        res = VULNERABILITIES[i].check(address);
        if (res < 0)
        {
            systemlog(LOG_AUTH | LOG_INFO, "Error checking device with address %s for %s.", btaddr_s, VULNERABILITIES[i].name);
        }
        else if (res > 0)
        {
            patched = 0;
            systemlog(LOG_AUTH | LOG_ALERT, "Device with address %s is vulnerable to %s", btaddr_s, VULNERABILITIES[i].name);
        }
    }
    if (patched)
    {
        systemlog(LOG_AUTH | LOG_INFO, "Device with address %s is not vulnerable to any tested exploits.", btaddr_s);
    }
}

void set_sigaction(void)
{
    struct sigaction sigact;
    sigact.sa_handler = cleanup;
    sigact.sa_flags = 0;
    if ((sigemptyset (&sigact.sa_mask) == -1 || sigaction (SIGINT, &sigact, NULL) == -1))
        systemlog(LOG_AUTH | LOG_ERR, "Error setting signact");
}

void setup(void)
{
    set_sigaction();
    logger_init(PROGRAM_NAME);
    systemlog(LOG_AUTH | LOG_INFO, "%s started", PROGRAM_NAME);
}

int setup_allowlist(char **allowed_addresses, char* allowlist_filename) {
    int num_allowlist, i;

    if ((num_allowlist = load_allowlist(allowlist_filename, allowed_addresses)) < 0)
    {
        systemlog(LOG_AUTH | LOG_ERR, "Error reading allowlist %s. Program Exiting", allowlist_filename);
        fprintf(stderr, "Error reading allowlist %s. Program Exiting\n", allowlist_filename);
        exit(EXIT_FAILURE);
    }

    if (!validate_allowlist(allowed_addresses, num_allowlist))
    {
        systemlog(LOG_AUTH | LOG_ERR, "Invalid allowlist %s. Program Exiting", allowlist_filename);
        fprintf(stderr, "Invalid allowlist %s. Program Exiting\n", allowlist_filename);
        exit(EXIT_FAILURE);
    }
    return num_allowlist;
}
