#ifndef __PEPSDEFS_H
#define __PEPSDEFS_H

#include <sys/user.h>

/* Program name */
#define PROGRAM_NAME "pepsal"

/* Minimal and maximal number of simultaneous connections */
#define PEP_MIN_CONNS 128
#define PEP_MAX_CONNS 25000

/* Default port number of pepsal listener */
#define PEP_DEFAULT_PORT 5000

/* Default receive buffer size of queuer thread */
#ifndef PAGE_SIZE
#define PAGE_SIZE (1 << 12)
#endif
#define QUEUER_BUF_SIZE PAGE_SIZE

/*
 * Size of buffer that is used for temporary error messages
 * composed by pep_error and pep_warning functions.
 */
#define PEP_ERRBUF_SZ 1024

/* Queue size of listener thread used for incomming TCP packets */
#define LISTENER_QUEUE_SIZE 60000

/* Number of pages reserved for send/receive buffers */
#define PEPBUF_PAGES 2

/* Number of worker threads in pepsal threads pool */
#define PEPPOOL_THREADS 10

/* Time interval, in seconds, between two dumps of the syntab table into the log file */
#define PEPLOGGER_INTERVAL (5 * 60)

/* Time interval, in seconds, between two rounds of the connections garbage collector */
#define PEP_GC_INTERVAL (15 * 3600)

/* Time duration, in seconds, before a connection is considered stale and garbage collected */
#define PEP_PENDING_CONN_LIFETIME (5 * 60)

/* Maximum size of a string to represent an IP address */
#define IP_ADDR_LEN 40

#ifndef offsetof
#define offsetof(type, field) \
    ((size_t) & (((type*)0)->field) - (size_t)((type*)0))
#endif /* !offsetof */

#define container_of(ptr, type, member) \
    (type*)((char*)(ptr)-offsetof(type, member))

#if (defined(__cplusplus) || defined(__GNUC__) || defined(__INTEL_COMPILER))
#define __inline inline
#else /* __cplusplus || __GNUC__ || __INTEL_COMPILER  */
#define __inline
#endif /* !__cplusplus && !__GNUC__ && !__INTEL_COMPILER */

#ifndef UNUSED
#if defined(__GNUC__)
#define UNUSED(x) x __attribute__((unused))
#else /* __GNUC__ */
#define UNUSED(x)
#endif /* !__GNUC__ */
#endif /* !UNUSED */

#endif /* !_PEPSDEFS_H */
