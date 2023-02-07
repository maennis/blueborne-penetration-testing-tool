#ifndef _BLUETOOTH_H_
#define _BLUETOOTH_H_

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <sys/socket.h>

#define BLUETOOTHADDRESSLEN 19
#define CVE_CHECK_ERR       -1
#define MAXNUMBTRESP        255

struct bluetooth_connection_info
{
    int device_id;
    int hci_socket;
};

typedef struct
{
    uint8_t dtd;
    uint8_t size;
    uint8_t data_type;
    uint16_t data_value;
} __attribute__((packed)) sdp_data_uuid16_t;

typedef struct 
{
    uint8_t dtd;
    uint8_t size;
    uint8_t data_type;
    uint32_t data_value;
} __attribute__((packed)) sdp_data_uuid32_t;

// Copied from BlueZ src/sdpd-request.c
typedef struct {
    uint32_t timestamp;
    union {
        uint16_t maxBytesSent;
        uint16_t lastIndexSent;
    } cStateValue;
} sdp_cont_state_bluez_t;

void cont_state_to_char(sdp_cont_state_bluez_t *cont_state, char *dest, uint8_t cont_len);

char * create_sdp_svc_attr_search_pdu(uint16_t service, char *continuation, size_t continuation_len);

char * create_sdp_svc_search_pdu(uint16_t service, char *continuation, size_t continuation_len);

int extract_cont_state_from_sdp(sdp_cont_state_bluez_t *cont_state, char *pdu);

int get_bluetooth_device_id(void);

int is_valid_address(char *address);

int is_vulnerable_to_cve_2017_1000250(bdaddr_t *target);

int open_bluetooth_device(const int device_id);

int make_hci_inquiry(bdaddr_t **addr_list, const struct bluetooth_connection_info *btinfo);

int set_l2cap_mtu(int sd, uint16_t mtu);

#endif //_BLUETOOTH_H_
