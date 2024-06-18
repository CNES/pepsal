/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005-2007
 * Copyleft Dan Kruchinin <dkruchinin@acm.org> 2010
 * Copyright CNES 2017
 * Copyright Thales Alenia Space 2024
 * See AUTHORS and COPYING before using this software.
 *
 */


/**
 * @brief Utilities for logging messages.
 *        Logs can be configured, at compile time, to go to the console,
 *        to use syslog, or both.
 *        Also define some utilities to ease embedding addresses into log
 *        messages.
 */


#ifndef __LOG_H
#define __LOG_H

#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#ifdef ENABLE_SYSLOG
#include <syslog.h>
#endif


/**
 * @brief Global flag to turn debugging on or off
 */
extern int DEBUG;


/**
 * @brief Outputs an error message to the console and forcibly exit
 *        the program.
 * @param function - name of the function the error message was
 *                   generated from
 * @param line - line number in the source code the message was
 *               generated from
 * @param fmt - printf-like format string to build the actual message
 * @param ... - printf-like variadic arguments to fill in the
 *              format string
 */
void __pep_error(const char* function, int line, const char* fmt, ...);


/**
 * @brief Outputs a warning message to the console.
 * @param function - name of the function the warning message was
 *                   generated from
 * @param line - line number in the source code the message was
 *               generated from
 * @param fmt - printf-like format string to build the actual message
 * @param ... - printf-like variadic arguments to fill in the
 *              format string
 */
void __pep_warning(const char* function, int line, const char* fmt, ...);


/**
 * @brief Convert a numerical MAC address to its textual representation.
 * @param ret - [Output] buffer to store the resulting string into
 * @param ether_host - 6-bytes numerical value of the MAC address
 */
void tomac(char* ret, const uint8_t ether_host[6]);


/**
 * @brief Convert a numerical IPv4 address to its textual representation.
 * @param ret - [Output] buffer to store the resulting string into
 * @param addr - 4-bytes numerical value of the IP address
 */
void toip(char* ret, const int addr);


/**
 * @brief Convert a numerical IPv6 address to its textual representation.
 * @param ret - [Output] buffer to store the resulting string into
 * @param addr - 16-bytes numerical value of the IP address
 */
void toip6(char* ret, const uint16_t addr[8]);


/**
 * @def CHECK_LOGGING
 * @brief Compile-time switch to enable or disable whole blocks of code
 *        depending on whether or not any logging capabilities is active.
 * @param ... - a block of code
 */
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


/**
 * @def SYSLOG_BEHAVIOUR
 * @brief Compile-time switch to enable or disable whole blocks of code
 *        depending on whether or not syslog logging is active.
 * @param ... - a block of code
 */
#ifdef ENABLE_SYSLOG
#define SYSLOG_BEHAVIOUR(...) __VA_ARGS__
#else
#define SYSLOG_BEHAVIOUR(...)
#endif


/**
 * @def STDERR_BEHAVIOUR
 * @brief Compile-time switch to enable or disable whole blocks of code
 *        depending on whether or not console logging is active.
 * @param ... - a block of code
 */
#ifdef ENABLE_STDERR
#define STDERR_BEHAVIOUR(...) __VA_ARGS__
#else
#define STDERR_BEHAVIOUR(...)
#endif


/**
 * @def pep_error(fmt, ...)
 * @brief Wrapper around syslog and __pep_error to simplify error
 *        reporting from within the code. Uses syslog logging, console
 *        logging, or both depending on compilation settings. Forcibly
 *        exit the program in either case.
 * @param fmt - printf-like format string to build the actual message
 * @param ... - printf-like variadic arguments to fill in the
 *              format string
 */
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


/**
 * @def pep_warning(fmt, ...)
 * @brief Wrapper around syslog and __pep_warning to simplify warning
 *        reporting from within the code. Uses syslog logging, console
 *        logging, or both depending on compilation settings.
 * @param fmt - printf-like format string to build the actual message
 * @param ... - printf-like variadic arguments to fill in the
 *              format string
 */
#define pep_warning(fmt, args...)                                              \
    SYSLOG_BEHAVIOUR(                                                          \
        syslog(LOG_WARNING, "%s():%d: " fmt, __FUNCTION__, __LINE__, ##args);) \
    __pep_warning(__FUNCTION__, __LINE__, fmt, ##args)


/**
 * @def PEP_DEBUG(fmt, ...)
 * @brief Wrapper around syslog and fprintf to simplify message
 *        reporting from within the code. Uses syslog logging,
 *        console logging, or both depending on compilation settings.
 * @param fmt - printf-like format string to build the actual message
 * @param ... - printf-like variadic arguments to fill in the
 *              format string
 */
#define PEP_DEBUG(fmt, args...)                                     \
    CHECK_LOGGING(                                                  \
        SYSLOG_BEHAVIOUR(                                           \
            syslog(LOG_DEBUG, "%s(): " fmt, __FUNCTION__, ##args);) \
            STDERR_BEHAVIOUR(                                       \
                fprintf(stderr, "[DEBUG] %s(): " fmt "\n", __FUNCTION__, ##args);))


/**
 * @def PEP_DEBUG_MAC(mac, fmt, ...)
 * @brief Wrapper around syslog and fprintf to simplify message
 *        reporting from within the code. Uses syslog logging,
 *        console logging, or both depending on compilation settings.
 *        Prepend the message with a textual representation of the
 *        MAC address passed as parameter.
 * @param mac - 6-bytes numerical MAC address to prepend into the message
 * @param fmt - printf-like format string to build the actual message
 * @param ... - printf-like variadic arguments to fill in the
 *              format string
 */
#define PEP_DEBUG_MAC(mac, fmt, args...)                                                   \
    CHECK_LOGGING(                                                                         \
        char __buf[MAC_ADDR_LEN];                                                          \
        tomac(__buf, mac);                                                                 \
        STDERR_BEHAVIOUR(                                                                  \
            fprintf(stderr, "[DEBUG] %s(): {%s} " fmt "\n", __FUNCTION__, __buf, ##args);) \
            SYSLOG_BEHAVIOUR(                                                              \
                syslog(LOG_DEBUG, "%s(): {%s} " fmt, __FUNCTION__, __buf, ##args);))


/**
 * @def PEP_DEBUG_DP(proxy, fmt, ...)
 * @brief Wrapper around syslog and fprintf to simplify message
 *        reporting from within the code. Uses syslog logging,
 *        console logging, or both depending on compilation settings.
 *        Prepend the message with a textual representation of the
 *        source IP address passed as parameter.
 * @param proxy - hashtable entry to retrieve the source IP address used
 *                to prepend into the message
 * @param fmt - printf-like format string to build the actual message
 * @param ... - printf-like variadic arguments to fill in the
 *              format string
 */
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


/**
 * @def nonblocking_err_p()
 * @brief Check if errno is related to nonblocking I/O.
 *        If it is in a set of nonblocking errors, it may be
 *        handled properly without program termination.
 */
#define nonblocking_err_p() ( \
    errno == EAGAIN || errno == EINPROGRESS || errno == EALREADY)

#endif // __LOG_H
