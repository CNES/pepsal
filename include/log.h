#ifndef __LOG_H
#define __LOG_H

#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#ifndef DISABLE_SYSLOG
#include <syslog.h>
#endif

extern int DEBUG;

void __pep_error(const char* function, int line, const char* fmt, ...);
void __pep_warning(const char* function, int line, const char* fmt, ...);
void toip(char* ret, int addr);
void toip6(char* ret, uint16_t addr[8]);

#ifdef DISABLE_SYSLOG

#define pep_error(fmt, args...) __pep_error(__FUNCTION__, __LINE__, fmt, ##args)

#define pep_warning(fmt, args...) \
    __pep_warning(__FUNCTION__, __LINE__, fmt, ##args)

#define PEP_DEBUG(fmt, args...)                                           \
    if (DEBUG) {                                                          \
        fprintf(stderr, "[DEBUG] %s(): " fmt "\n", __FUNCTION__, ##args); \
    }

#define PEP_DEBUG_DP(proxy, fmt, args...)      \
    if (DEBUG) {                               \
        char __buf[IP_ADDR_LEN];               \
        toip6(__buf, (proxy)->src.addr);       \
        fprintf(stderr,                        \
            "[DEBUG] %s(): {%s:%d} " fmt "\n", \
            __FUNCTION__,                      \
            __buf,                             \
            (proxy)->src.port,                 \
            ##args);                           \
    }
#else

#define pep_error(fmt, args...)        \
    syslog(LOG_ERR,                    \
        "%s():%d: " fmt " (errno %d)", \
        __FUNCTION__,                  \
        __LINE__,                      \
        ##args,                        \
        errno);                        \
    __pep_error(__FUNCTION__, __LINE__, fmt, ##args)

#define pep_warning(fmt, args...)                                         \
    syslog(LOG_WARNING, "%s():%d: " fmt, __FUNCTION__, __LINE__, ##args); \
    __pep_warning(__FUNCTION__, __LINE__, fmt, ##args)

#define PEP_DEBUG(fmt, args...)                                           \
    if (DEBUG) {                                                          \
        fprintf(stderr, "[DEBUG] %s(): " fmt "\n", __FUNCTION__, ##args); \
        syslog(LOG_DEBUG, "%s(): " fmt, __FUNCTION__, ##args);            \
    }

#define PEP_DEBUG_DP(proxy, fmt, args...)      \
    if (DEBUG) {                               \
        char __buf[IP_ADDR_LEN];               \
        toip6(__buf, (proxy)->src.addr);       \
        fprintf(stderr,                        \
            "[DEBUG] %s(): {%s:%d} " fmt "\n", \
            __FUNCTION__,                      \
            __buf,                             \
            (proxy)->src.port,                 \
            ##args);                           \
        syslog(LOG_DEBUG,                      \
            "%s(): {%s:%d} " fmt,              \
            __FUNCTION__,                      \
            __buf,                             \
            (proxy)->src.port,                 \
            ##args);                           \
    }
#endif

/*
 * Check if errno is related to nonblocking I/O.
 * If it is in a set of nonblocking errors, it may be
 * handled properly without program termination.
 */
#define nonblocking_err_p() ( \
    errno == EAGAIN || errno == EINPROGRESS || errno == EALREADY)

#endif // __LOG_H
