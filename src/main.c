#include <syslog.h>

// Custom Imports
#include "logger.h"

#define PROGRAM_NAME    "bluebornepentesttool"

int main(int argc, char**argv) {
    logger_init(PROGRAM_NAME);
    systemlog(LOG_AUTH | LOG_INFO, "%s started", PROGRAM_NAME);
    logger_close();
    return 0;
}
