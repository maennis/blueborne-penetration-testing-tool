#ifndef _LOGGER_H
#define _LOGGER_H

void logger_init(const char *program_name);

void systemlog(int priority, const char *fmt, ...);

void logger_close(void);

#endif //_LOGGER_H
