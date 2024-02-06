/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005-2007
 * Copyleft Dan Kruchinin <dkruchinin@acm.org> 2010
 * See AUTHORS and COPYING before using this software.
 *
 *
 *
 */

#ifndef __PEPSAL_H
#define __PEPSAL_H

#include "atomic.h"
#include "congestionlist.h"
#include "list.h"
#include "pepdefs.h"
#include <sys/epoll.h>
#include <sys/types.h>

enum proxy_status {
    PST_CLOSED = 0,
    PST_OPEN,
    PST_CONNECT,
    PST_PENDING,
    PST_INVAL,
};

/* I/O flags of PEP endpoint */
#define PEP_IORDONE 0x01
#define PEP_IOWDONE 0x02
#define PEP_IOEOF 0x04
#define PEP_IOERR 0x08

struct pep_proxy;

struct pep_pipes {
    union {
        int fds[2];
        struct {
            int out;
            int in;
        };
    };
};

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

struct pep_proxy* alloc_proxy(void);
void destroy_proxy(struct pep_proxy* proxy, int epoll_fd);

#endif /* !__PEPSAL_H */
