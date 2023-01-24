#ifndef _BLUETOOTH_H_
#define _BLUETOOTH_H_

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define BLUETOOTHADDRESSLEN 19
#define DEVICENAMELEN       248
#define INQUIRYLEN          10 // This value is multiplied by 1.28 seconds to get the hci_inquiry length
#define MAXNUMBTRESP        255

struct bluetooth_connection_info
{
    int device_id;
    int hci_socket;
};

int get_bluetooth_device_id(void);

int is_valid_address(char *address);

int open_bluetooth_device(const int device_id);

int make_hci_inquiry(bdaddr_t **addr_list, const struct bluetooth_connection_info *btinfo);

#endif //_BLUETOOTH_H_
