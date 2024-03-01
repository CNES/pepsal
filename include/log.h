#ifndef __LOG_H
#define __LOG_H

#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#ifdef ENABLE_SYSLOG
#include <syslog.h>
#endif

extern int DEBUG;

void __pep_error(const char* function, int line, const char* fmt, ...);
void __pep_warning(const char* function, int line, const char* fmt, ...);
void tomac(char* ret, const uint8_t ether_host[6]);
void toip(char* ret, const int addr);
void toip6(char* ret, const uint16_t addr[8]);

#if defined(ENABLE_SYSLOG) || defined(ENABLE_STDERR)
#define CHECK_LOGGING(...) \
    do {                   \
        if (DEBUG) {       \
            __VA_ARGS__    \
        }                  \
    } while (0)
#else
#define CHECK_LOGGING(...)
#endif

#ifdef ENABLE_SYSLOG
#define SYSLOG_BEHAVIOUR(...) __VA_ARGS__
#else
#define SYSLOG_BEHAVIOUR(...)
#endif

#ifdef ENABLE_STDERR
#define STDERR_BEHAVIOUR(...) __VA_ARGS__
#else
#define STDERR_BEHAVIOUR(...)
#endif

#define pep_error(fmt, args...)            \
    SYSLOG_BEHAVIOUR(                      \
        syslog(LOG_ERR,                    \
            "%s():%d: " fmt " (errno %d)", \
            __FUNCTION__,                  \
            __LINE__,                      \
            ##args,                        \
            errno);                        \
        closelog();)                       \
    __pep_error(__FUNCTION__, __LINE__, fmt, ##args)

#define pep_warning(fmt, args...)                                              \
    SYSLOG_BEHAVIOUR(                                                          \
        syslog(LOG_WARNING, "%s():%d: " fmt, __FUNCTION__, __LINE__, ##args);) \
    __pep_warning(__FUNCTION__, __LINE__, fmt, ##args)

#define PEP_DEBUG(fmt, args...)                                     \
    CHECK_LOGGING(                                                  \
        SYSLOG_BEHAVIOUR(                                           \
            syslog(LOG_DEBUG, "%s(): " fmt, __FUNCTION__, ##args);) \
            STDERR_BEHAVIOUR(                                       \
                fprintf(stderr, "[DEBUG] %s(): " fmt "\n", __FUNCTION__, ##args);))

#define PEP_DEBUG_MAC(mac, fmt, args...)                                                   \
    CHECK_LOGGING(                                                                         \
        char __buf[MAC_ADDR_LEN];                                                          \
        tomac(__buf, mac);                                                                 \
        STDERR_BEHAVIOUR(                                                                  \
            fprintf(stderr, "[DEBUG] %s(): {%s} " fmt "\n", __FUNCTION__, __buf, ##args);) \
            SYSLOG_BEHAVIOUR(                                                              \
                syslog(LOG_DEBUG, "%s(): {%s} " fmt, __FUNCTION__, __buf, ##args);))

#define PEP_DEBUG_DP(proxy, fmt, args...)          \
    CHECK_LOGGING(                                 \
        char __buf[IP_ADDR_LEN];                   \
        toip6(__buf, (proxy)->src.addr);           \
        STDERR_BEHAVIOUR(                          \
            fprintf(stderr,                        \
                "[DEBUG] %s(): {%s:%d} " fmt "\n", \
                __FUNCTION__,                      \
                __buf,                             \
                (proxy)->src.port,                 \
                ##args);)                          \
            SYSLOG_BEHAVIOUR(                      \
                syslog(LOG_DEBUG,                  \
                    "%s(): {%s:%d} " fmt,          \
                    __FUNCTION__,                  \
                    __buf,                         \
                    (proxy)->src.port,             \
                    ##args);))

/*
 * Check if errno is related to nonblocking I/O.
 * If it is in a set of nonblocking errors, it may be
 * handled properly without program termination.
 */
#define nonblocking_err_p() ( \
    errno == EAGAIN || errno == EINPROGRESS || errno == EALREADY)

#endif // __LOG_H
