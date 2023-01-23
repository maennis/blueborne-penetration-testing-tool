#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

// Custom Imports
#include "bluetooth.h"
#include "logger.h"

#define POLL_INTERVAL   30 // In seconds
#define PROGRAM_NAME    "bluebornepentesttool"
#define TRUE            1

_Noreturn void cleanup(int signal);
void set_sigaction(void);
void setup(void);

int main(int argc, char**argv) {
    struct bluetooth_connection_info bt_info;
    bdaddr_t *bt_address_list;
    char btaddr_s[BLUETOOTHADDRESSLEN] = { 0 };
    int i, responses = 0;
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

    bt_address_list = (bdaddr_t *) malloc(sizeof(bdaddr_t) * MAXNUMBTRESP);
    
    while(TRUE)
    {
        systemlog(LOG_AUTH | LOG_INFO, "Begining HCI inquiry");
        responses = make_hci_inquiry(&bt_address_list, &bt_info);
        systemlog(LOG_AUTH | LOG_INFO, "Concluded inquiry.  Found %d devices", responses);
        for (i = 0; i < responses; i++)
        {
            ba2str((bt_address_list + i), btaddr_s);
            systemlog(LOG_AUTH | LOG_INFO, "Device %d address: %s", i, btaddr_s);
        }

        sleep(POLL_INTERVAL);
    }
    return 0;
}

_Noreturn void cleanup(int signal)
{
    logger_close();
    systemlog(LOG_AUTH | LOG_INFO, "Shutting down %s", PROGRAM_NAME);
    exit(EXIT_SUCCESS);
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
