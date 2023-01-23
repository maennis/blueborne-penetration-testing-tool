#include <signal.h>
#include <stdlib.h>
#include <syslog.h>

// Custom Imports
#include "logger.h"

#define NULL            0
#define PROGRAM_NAME    "bluebornepentesttool"
#define TRUE            1

_Noreturn void cleanup(void);
void set_sigaction(void);
void setup(void);

int main(int argc, char**argv) {
    setup();
    while(TRUE)
    {

    }
    return 0;
}

_Noreturn void cleanup(void)
{
    logger_close();
    systemlog(LOG_AUTH | LOG_INFO, "Shutting down %s", PROGRAM_NAME);
    exit(EXIT_SUCCESS);
}

void set_sigaction(void)
{
    struct sigaction sigact;
    sigact.sa_handler = cleanup;
    sigact.sa_flags = 0;
    if ((sigemptyset (&sigact.sa_mask) == -1 || sigaction (SIGINT, &sigact, NULL) == -1))
        systemlog(LOG_AUTH | LOG_ERR, "Error setting signact");
}

void setup(void)
{
    set_sigaction();
    logger_init(PROGRAM_NAME);
    systemlog(LOG_AUTH | LOG_INFO, "%s started", PROGRAM_NAME);
}
