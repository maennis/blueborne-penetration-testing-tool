#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bluetooth.h"

char * create_sdp_svs_search_pdu(uint16_t service, char *continuation, size_t continuation_len)
{
    char *pdu = (char *) malloc(MTU);
    memset(pdu, 0, MTU);
    // PDU header
    sdp_pdu_hdr_t *pdu_header = (sdp_pdu_hdr_t *) pdu;
    pdu_header->pdu_id = SDP_SVC_SEARCH_REQ;
    pdu_header->tid = 0x0000;
    pdu_header->plen = htons(SDPPDUATTRLEN + continuation_len);
    // Create a PDU data element
    sdp_data_uuid16_t *sdp_pdu_data = (sdp_data_uuid16_t *) (pdu + sizeof(sdp_pdu_hdr_t));
    sdp_pdu_data->dtd = 0x35; // Set type and size descriptors
    sdp_pdu_data->size = 0x03;
    sdp_pdu_data->data_type = 0x19;
    sdp_pdu_data->data_value = htons(service);

    uint16_t *max_service_record = (uint16_t *) (pdu + sizeof(sdp_pdu_hdr_t) + sizeof(sdp_data_uuid16_t));
    *max_service_record = htons(0x0100);

    char *continuation_state = (char *) (pdu + sizeof(sdp_pdu_hdr_t) + sizeof(sdp_data_uuid16_t) + 2 * sizeof(uint8_t));
    if (continuation_len > 1)
    {
        memcpy(continuation_state, continuation, continuation_len);
    } else {
        *continuation_state = 0x00;
    }

    return pdu;
}

int get_bluetooth_device_id(void)
{
    return hci_get_route(NULL);
}

int is_valid_address(char *address)
{
    return bachk(address) >= 0;
}

int is_vulnerable_to_cve_2017_1000250(bdaddr_t *target)
{
    struct sockaddr_l2 addr = { 0 };
    int sd, status, continuation_len = 1;
    int16_t mtu = MTU;
    char *pdu, target_s[19],;

    // Return a negative integer indicating failure to create socket
    if ((sd = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)) < 0)
        return -1;
    // Reduce the size of the incoming and outgoing MTU to force the use of a continuation state
    if ((status = set_l2cap_mtu(sd, mtu)) < 0)
        return -2;

    addr.l2_bdaddr = *target;
    addr.l2_family = AF_BLUETOOTH;
    addr.l2_psm = htobs(1);

    pdu = create_sdp_svs_search_pdu(0x0100, 0x00, continuation_len);

    if (connect(sd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        return -3;
    // Send initial PDU
    if ((status = write(sd, pdu, SDPPDUBASELEN + continuation_len)) < 0)
        return -4;

    free(pdu);
    close(sd);
    return status;
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

int set_l2cap_mtu(int sd, uint16_t mtu)
{
    struct l2cap_options opts;
    int len = sizeof(opts);
    int status = getsockopt(sd, SOL_L2CAP, L2CAP_OPTIONS, &opts, &len);
    if (status == 0)
    {
        opts.imtu = opts.omtu = mtu;
        status = setsockopt(sd, SOL_L2CAP, L2CAP_OPTIONS, &opts, len);
    }
    return status;
}
