#ifndef _UTILS_H
#define _UTILS_H

int load_allowlist(char *filename, char **allowed_addresses);

int validate_allowlist(char **allowed_addresses, int num_addresses);

int is_in_allowlist(char *address, char **allowed_addresses, int num_addresses);

#endif // _UTILS_H
