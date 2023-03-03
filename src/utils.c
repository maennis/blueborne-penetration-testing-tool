#include <ctype.h>
#include <string.h>
#include <sys/file.h>

#include "utils.h"
#include "bluetooth.h"

int is_number(char * str)
{
    int i, len = strlen(str);
    for (i = 0; i < len; i++)
        if (!isdigit(str[i]))
            return 0;
    return 1;
}

int load_allowlist(char *filename, char **allowed_addresses)
{
    int count = 0;
    char *buf = NULL;
    size_t n;
    ssize_t read;
    FILE *fp;
    fp = fopen(filename, "r");
    if (fp == NULL) {
        return -1;
    }
    while((read = getline(&buf, &n, fp)) != -1)
    {
        if (ferror(fp))
            return -2;
        if (strlen(buf) >= BLUETOOTHADDRESSLEN)
            return -3;
        if (buf[read - 1] == '\n')
            buf[read - 1] = '\0';
        strcpy(allowed_addresses[count], buf);
        count++;
    }
    fclose(fp);
    return count;
}

int validate_allowlist(char **allowed_addresses, int num_addresses)
{
    int i;
    for (i = 0; i < num_addresses; i++)
        if (!is_valid_address(allowed_addresses[i]))
            return 0;
    return 1;
}

int is_in_allowlist(char *address, char **allowed_addresses, int num_addresses)
{
    int i;
    for (i = 0; i < num_addresses; i++)
        if (strcmp(address, allowed_addresses[i]) == 0)
            return 1;
    return 0;
}
