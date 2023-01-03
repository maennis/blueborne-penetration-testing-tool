#include <stdarg.h> 
#include <syslog.h>

// Custom Imports
#include "logger.h"

void logger_init(const char *program_name) {
    openlog(program_name, LOG_CONS, LOG_AUTH);
}

void systemlog(int priority, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
}

void logger_close(void) {
    closelog();
}
