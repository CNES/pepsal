/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005-2007
 * Copyleft Dan Kruchinin <dkruchinin@acm.org> 2010
 * See AUTHORS and COPYING before using this software.
 *
 */

#ifndef __PEPSAL_H
#define __PEPSAL_H

#include "atomic.h"
#include "list.h"
#include <sys/epoll.h>
#include <sys/types.h>


/**
 * @enum proxy_status
 * @brief Statuses a connection proxy can have
 */
enum proxy_status {
    PST_CLOSED = 0,
    PST_OPEN,
    PST_CONNECT,
    PST_PENDING,
    PST_PENDING_IN,
    PST_INVAL,
};

/* I/O flags of PEP endpoint */
#define PEP_IORDONE 0x01
#define PEP_IOWDONE 0x02
#define PEP_IOEOF 0x04
#define PEP_IOERR 0x08

struct pep_proxy;


/**
 * @struct pep_pipes
 * @brief Storage for file-descriptors of input and output ends of a
 *        unidirectionnal pipe used by a connection proxy. Using an
 *        union simplifies access to either an array of 2 elements or
 *        to each element individually.
 */
struct pep_pipes {
    union {
        int fds[2];
        struct {
            int out;
            int in;
        };
    };
};


/**
 * @struct pep_endpoint
 * @brief One end of a connection handled by PEPSal. Either the input
 *        socket created by `accept` or the associated output socket
 *        created to reach the initial destination.
 */
struct pep_endpoint {
    uint16_t addr[8];
    unsigned short port;
    int fd;
    struct pep_pipes buf;
    struct pep_proxy* owner;
    struct epoll_event epoll_event;
    unsigned char iostat;
    int delta;
};

#define PROXY_ENDPOINTS 2


/**
 * @struct pep_proxy
 * @brief Connection proxy used to link two endpoints (sockets)
 *        together in an effort to ease packet transition form one to
 *        the other.
 */
struct pep_proxy {
    enum proxy_status status;
    struct list_node lnode;
    struct list_node qnode;

    union {
        struct pep_endpoint endpoints[PROXY_ENDPOINTS];
        struct {
            struct pep_endpoint src;
            struct pep_endpoint dst;
        };
    };

    time_t syn_time;
    time_t last_rxtx;
    atomic_t refcnt;
    int enqueued;
};


/**
 * @brief Allocate a new, empty, connection proxy and configure it for
 *        linked-list insertion and events polling.
 * @return a newly allocated proxy, or NULL in case of an error
 */
struct pep_proxy* alloc_proxy(void);


/**
 * @brief Remove a connection proxy from the hashtable and close all
 *        associated file-descriptors.
 * @param proxy - the proxy to close
 * @param epoll_fd - the epoll file-descriptor to properly clear events
 *                   polling associated to this proxy
 */
void destroy_proxy(struct pep_proxy* proxy, int epoll_fd);


/**
 * @brief Reclaim a connection proxy memory if no other thread is
 *        holding onto it.
 * @param proxy - the proxy to free
 */
void unpin_proxy(struct pep_proxy* proxy);

#endif /* !__PEPSAL_H */
