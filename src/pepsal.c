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
    int i, bkp;
    struct pep_endpoint* endp;
    struct pep_proxy* proxy = calloc(1, sizeof(*proxy));

    if (!proxy) {
        errno = ENOMEM;
        return NULL;
    }

    pthread_rwlockattr_t attr;
    if (pthread_rwlockattr_init(&attr) != 0) {
        bkp = errno;
        free(proxy);
        errno = bkp;
        return NULL;
    }

    if (pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0
        || pthread_rwlock_init(&proxy->lock, &attr) != 0) {
        bkp = errno;
        pthread_rwlockattr_destroy(&attr);
        free(proxy);
        errno = bkp;
        return NULL;
    }

    pthread_rwlockattr_destroy(&attr);

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

    PEP_DEBUG_DP(proxy, "Destroy proxy");

    syntab_delete(proxy);
    proxy->status = PST_CLOSED;

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

void lock_read_proxy(struct pep_proxy* proxy)
{
    PEP_DEBUG("READ lock for proxy with port %u", proxy->src.port);
    pthread_rwlock_rdlock(&proxy->lock);
}

void unlock_read_proxy(struct pep_proxy* proxy)
{
    PEP_DEBUG("READ unlock for proxy with port %u", proxy->src.port);
    pthread_rwlock_unlock(&proxy->lock);
}

void lock_write_proxy(struct pep_proxy* proxy)
{
    PEP_DEBUG("WRITE lock for proxy with port %u", proxy->src.port);
    pthread_rwlock_wrlock(&proxy->lock);
}

void unlock_write_proxy(struct pep_proxy* proxy)
{
    PEP_DEBUG("WRITE unlock for proxy with port %u", proxy->src.port);
    pthread_rwlock_unlock(&proxy->lock);
}
