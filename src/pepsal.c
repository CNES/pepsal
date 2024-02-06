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
    struct pep_proxy* proxy = calloc(1, sizeof(*proxy));
    int i;
    struct pep_endpoint* endp;

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
        goto out;
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

out:
    if (atomic_dec(&proxy->refcnt) == 1) {
        PEP_DEBUG_DP(proxy, "Free proxy");
        assert(atomic_read(&proxy->refcnt) == 0);
        free(proxy);
    }
}
