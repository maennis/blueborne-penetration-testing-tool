#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

// Custom Imports
#include "bluetooth.h"
#include "logger.h"
#include "utils.h"

#define ALLOWLIST       "allowlist.txt"
#define POLL_INTERVAL   30 // In seconds
#define PROGRAM_NAME    "bluebornepentesttool"
#define TRUE            1

_Noreturn void cleanup(int signal);
void process_device(bdaddr_t *address, int *processed_bt_addresses, char processed_addresses[MAXNUMBTRESP][BLUETOOTHADDRESSLEN], int num_allowlist, char **allowed_addresses);
void set_sigaction(void);
void setup(void);

int main(int argc, char**argv) {
    struct bluetooth_connection_info bt_info;
    bdaddr_t *bt_address_list, btaddr;
    char processed_bt_addresses[MAXNUMBTRESP][BLUETOOTHADDRESSLEN], **allowed_addresses;
    int i, responses, num_allowlist, num_processed_bt_address = 0;
    setup();

    if ((bt_info.device_id = get_bluetooth_device_id()) < 0)
    {
        systemlog(LOG_AUTH | LOG_ERR, "Cannot find bluetooth adapter. Program Exiting");
        exit(EXIT_FAILURE);
    }

    if ((bt_info.hci_socket = open_bluetooth_device(bt_info.device_id)) < 0)
    {
        systemlog(LOG_AUTH | LOG_ERR, "Cannot open HCI socket. Program Exiting");
        exit(EXIT_FAILURE);
    }
    // Allocate memory
    bt_address_list = (bdaddr_t *) malloc(sizeof(bdaddr_t) * MAXNUMBTRESP);
    memset(processed_bt_addresses, 0, MAXNUMBTRESP * BLUETOOTHADDRESSLEN);
    allowed_addresses = (char **) malloc(sizeof(char *) * MAXALLOWLISTSIZE);
    for (i = 0; i < MAXALLOWLISTSIZE; i++)
        allowed_addresses[i] = (char *) malloc(sizeof(char) * BLUETOOTHADDRESSLEN);

    if ((num_allowlist = load_allowlist(ALLOWLIST, allowed_addresses)) < 0)
    {
        systemlog(LOG_AUTH | LOG_ERR, "Error reading allowlist. Program Exiting");
        exit(EXIT_FAILURE);
    }

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
        sleep(POLL_INTERVAL);
    }

    free(bt_address_list);
    for (i = 0; i < MAXALLOWLISTSIZE; i++);
        free(allowed_addresses[i]);
    free(allowed_addresses);

    return 0;
}

_Noreturn void cleanup(int signal)
{
    logger_close();
    systemlog(LOG_AUTH | LOG_INFO, "Shutting down %s", PROGRAM_NAME);
    exit(EXIT_SUCCESS);
}

void process_device(bdaddr_t *address, int *processed_bt_addresses, char processed_addresses[MAXNUMBTRESP][BLUETOOTHADDRESSLEN], int num_allowlist, char **allowed_addresses)
{
    int i;
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
