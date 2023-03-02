#ifndef _UTILS_H
#define _UTILS_H

#include "bluetooth.h"

#define MAX_ALLOWLIST_SIZE  32
#define MAX_CVE_NAME_SIZE   31

typedef int (*cve_vulnerability_check)(bdaddr_t *address);

typedef struct
{
    char name[MAX_CVE_NAME_SIZE];
    cve_vulnerability_check check;
} cve_check;

int load_allowlist(char *filename, char **allowed_addresses);

int validate_allowlist(char **allowed_addresses, int num_addresses);

int is_in_allowlist(char *address, char **allowed_addresses, int num_addresses);

#endif // _UTILS_H
