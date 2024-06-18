/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005
 * Copyleft Dan Kruchining <dkruchinin@acm.com> 2010
 * Copyright CNES 2017
 * Copyright Thales Alenia Space 2024
 * See AUTHORS and COPYING before using this software.
 *
 */


#include "pepsal.h"
#include "conntrack.h"
#include "log.h"
#include "syntab.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

struct pep_proxy* alloc_proxy(void)
{
    int i;
    struct pep_endpoint* endp;
    struct pep_proxy* proxy = calloc(1, sizeof(*proxy));

    if (!proxy) {
        errno = ENOMEM;
        return NULL;
    }

    list_init_node(&proxy->lnode);
    list_init_node(&proxy->qnode);
    proxy->status = PST_INVAL;
    atomic_set(&proxy->refcnt, 1);

    for (i = 0; i < PROXY_ENDPOINTS; i++) {
        endp = &proxy->endpoints[i];
        endp->fd = -1;
        endp->owner = proxy;
        endp->epoll_event.data.ptr = endp;
        endp->iostat = 0;
        endp->epoll_event.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    }

    return proxy;
}

void destroy_proxy(struct pep_proxy* proxy, int epoll_fd)
{
    int i;

    if (proxy->status == PST_CLOSED) {
        unpin_proxy(proxy);
        return;
    }

    proxy->status = PST_CLOSED;
    PEP_DEBUG_DP(proxy, "Destroy proxy");

    SYNTAB_LOCK_WRITE();
    syntab_delete(proxy);
    proxy->status = PST_CLOSED;
    SYNTAB_UNLOCK_WRITE();

    for (i = 0; i < PROXY_ENDPOINTS; i++) {
        if (proxy->endpoints[i].fd >= 0) {
            fcntl(proxy->endpoints[i].fd, F_SETFL, O_SYNC);
            epoll_ctl(epoll_fd,
                EPOLL_CTL_DEL,
                proxy->endpoints[i].fd,
                &proxy->endpoints[i].epoll_event);
            close(proxy->endpoints[i].fd);
        }
        close(proxy->endpoints[i].buf.in);
        close(proxy->endpoints[i].buf.out);
    }
    decrease_connection_count();
    unpin_proxy(proxy);
}

void unpin_proxy(struct pep_proxy* proxy)
{
    if (atomic_dec(&proxy->refcnt) == 1) {
        PEP_DEBUG_DP(proxy, "Free proxy");
        assert(atomic_read(&proxy->refcnt) == 0);
        free(proxy);
    }
}
