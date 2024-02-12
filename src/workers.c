#define _GNU_SOURCE
#include "workers.h"
#include "list.h"
#include "log.h"
#include "pepqueue.h"
#include "pepsal.h"

#include <fcntl.h>
#include <string.h>

static inline ssize_t
pep_receive(struct pep_endpoint* endp)
{
    ssize_t rb;

    if (endp->iostat & (PEP_IOERR | PEP_IOEOF)) {
        return 0;
    }

    rb = splice(endp->fd,
        NULL,
        endp->buf.in,
        NULL,
        PAGE_SIZE,
        SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK);

    if (rb < 0) {
        if (nonblocking_err_p()) {
            endp->iostat |= PEP_IORDONE;
            return 0;
        }

        endp->iostat |= PEP_IOERR;
        return -1;
    } else if (rb == 0) {
        endp->iostat |= PEP_IOEOF;
        return 0;
    }
    return rb;
}

static inline ssize_t
pep_send(struct pep_endpoint* from, int to_fd)
{
    ssize_t wb;

    if (from->iostat & (PEP_IOERR | PEP_IOWDONE)) {
        return 0;
    }

    wb = splice(from->buf.out,
        NULL,
        to_fd,
        NULL,
        PAGE_SIZE,
        SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK);

    if (wb < 0) {
        if (nonblocking_err_p()) {
            from->iostat |= PEP_IOWDONE;
            return 0;
        }

        from->iostat |= PEP_IOERR;
        return -1;
    }
    return wb;
}

static inline void
pep_proxy_data(struct pep_endpoint* from, struct pep_endpoint* to, int epoll_fd)
{
    ssize_t rb, wb;
    int ret;

    rb = wb = 1;
    while ((wb > 0) || (rb > 0)) {
        from->delta += rb = pep_receive(from);
        from->delta -= wb = pep_send(from, to->fd);
    }

    if (from->iostat & PEP_IOERR) {
        return;
    }

    /*
     * Receiving buffer has no space or EOF was reached from the peer.
     * Stop wait for incoming data on this FD.
     */
    if ((from->delta > 0) || (from->iostat & PEP_IOEOF)) {
        from->epoll_event.events &= ~EPOLLIN;
    } else if (from->iostat & PEP_IORDONE) {
        from->epoll_event.events |= EPOLLIN;
    }
    ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, from->fd, &from->epoll_event);
    if (ret < 0) {
        pep_error("epoll_ctl: [%s:%d]", strerror(errno), errno);
    }

    /*
     * All available data was transmitted to the peer
     * Stop wait when FD will be ready for write.
     */
    if (from->delta == 0) {
        to->epoll_event.events &= ~EPOLLOUT;
    } else { /* There exists some data to write. Wait until we can transmit it. */
        to->epoll_event.events |= EPOLLOUT;
    }
    ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, to->fd, &to->epoll_event);
    if (ret < 0) {
        pep_error("epoll_ctl: [%s:%d]", strerror(errno), errno);
    }
}

void* workers_loop(void* arg)
{
    struct worker_thread_arguments* args = (struct worker_thread_arguments*)arg;
    struct pep_proxy* proxy;
    struct list_head local_list;
    int ready_items;

    PEPQUEUE_LOCK(args->active_queue);
    for (;;) {
        list_init_head(&local_list);
        ready_items = 0;
        PEPQUEUE_WAIT(args->active_queue);

        while (args->active_queue->num_items > 0) {
            proxy = pepqueue_dequeue(args->active_queue);
            PEPQUEUE_UNLOCK(args->active_queue);

            pep_proxy_data(&proxy->src, &proxy->dst, args->epoll_fd);
            pep_proxy_data(&proxy->dst, &proxy->src, args->epoll_fd);

            proxy->last_rxtx = time(NULL);
            list_add2tail(&local_list, &proxy->qnode);
            ready_items++;

            PEPQUEUE_LOCK(args->active_queue);
        }

        PEPQUEUE_LOCK(args->ready_queue);
        pepqueue_enqueue_list(args->ready_queue, &local_list, ready_items);
        PEPQUEUE_UNLOCK(args->ready_queue);
        PEPQUEUE_WAKEUP_WAITERS(args->ready_queue);
    }
}
