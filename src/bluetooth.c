#include <stdlib.h>
#include <string.h>

#include "bluetooth.h"

int get_bluetooth_device_id(void)
{
    return hci_get_route(NULL);
}

int open_bluetooth_device(const int device_id)
{
    return hci_open_dev(device_id);
}

int make_hci_inquiry(bdaddr_t **addr_list, const struct bluetooth_connection_info *btinfo)
{
    int inqlen, max_num_resp, flags, num_resp, i;
    inquiry_info *inqinfo = NULL;
    inqlen = INQUIRYLEN;
    max_num_resp = MAXNUMBTRESP;
    // Allocate memory for maximum number of potential devices
    inqinfo = (inquiry_info*)malloc(max_num_resp * sizeof(inquiry_info));

    flags = IREQ_CACHE_FLUSH;

    // Query nearby devices for information
    num_resp = hci_inquiry(btinfo->device_id, inqlen, max_num_resp, NULL, &inqinfo, flags);
    
    for (i = 0; i < num_resp; i++)
    {
        memcpy((*addr_list) + i, &(inqinfo + i)->bdaddr, sizeof(bdaddr_t));
    }

    return num_resp;
}
