#ifndef _UTILS_H
#define _UTILS_H

#include "bluetooth.h"

#define MAXALLOWLISTSIZE    32
#define MAXCVENAMESIZE      17
#define NUM_VULNERABILITIES 3

typedef int (*cve_vulnerability_check)(bdaddr_t *address);

typedef struct
{
    char name[MAXCVENAMESIZE];
    cve_vulnerability_check check;
} cve_check;

int load_allowlist(char *filename, char **allowed_addresses);

int validate_allowlist(char **allowed_addresses, int num_addresses);

int is_in_allowlist(char *address, char **allowed_addresses, int num_addresses);

#endif // _UTILS_H
