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


#define _GNU_SOURCE
#include "poller.h"
#include "conntrack.h"
#include "list.h"
#include "log.h"
#include "pepqueue.h"
#include "pepsal.h"
#include "syntab.h"

#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Signal number that is sent to poller thread when
 * new incomming connection appears
 */
#define POLLER_NEWCONN_SIG SIGUSR1

static void
setup_socket(int fd)
{
    struct timeval t = { 0, 10000 };
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t));
    PEP_DEBUG("Socket %d: Setting up timeouts and syncronous mode.", fd);
}

/* An empty signal handler. It is only needed to interrupt poll() */
static void
poller_sighandler(__attribute__((unused)) int signum)
{
    /*
     * Do not use PEP_DEBUG here, as both syslog and fprintf are
     * AS-unsafe in POSIX implementation.
     * Calling them within a signal handler invokes undefined behavior.
     */
}

void block_poller_signal(void)
{
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, POLLER_NEWCONN_SIG);
    sigaddset(&sigset, SIGPIPE);
    sigprocmask(SIG_BLOCK, &sigset, NULL);
}

void* poller_loop(void* arg)
{
    struct poller_thread_arguments* args = (struct poller_thread_arguments*)arg;
    int epollret, num_works, iostat;
    const unsigned int event_handlers = 2 * get_max_connections();
    struct pep_proxy* proxy;
    struct pep_endpoint* endp;
    struct epoll_event *event, events[event_handlers];
    struct list_node *entry, *safe;
    struct list_head local_list;
    sigset_t sigset;
    struct sigaction sa;

    sigemptyset(&sigset);
    sigaddset(&sigset, POLLER_NEWCONN_SIG);
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = poller_sighandler;
    sa.sa_mask = sigset;
    if (sigaction(POLLER_NEWCONN_SIG, &sa, NULL) < 0) {
        pep_error("sigaction() error!");
    }

    sigprocmask(SIG_UNBLOCK, &sigset, NULL);

    for (;;) {
        list_init_head(&local_list);

        epollret = epoll_wait(args->epoll_fd, events, event_handlers, -1);
        if (epollret < 0) {
            if (errno == EINTR) {
                /* It seems that new client just appered. Renew descriptors. */
                continue;
            }

            pep_error("poll() error!");
        } else if (epollret == 0) {
            continue;
        }

        num_works = 0;
        for (size_t i = 0; i < epollret; ++i) {
            event = &events[i];
            endp = (struct pep_endpoint*)event->data.ptr;
            proxy = (struct pep_proxy*)endp->owner;

            if (!event->events) {
                continue;
            }

            if (proxy->enqueued) {
                continue;
            }

            switch (proxy->status) {
            case PST_CONNECT: {
                int ret, connerr;
                socklen_t errlen = sizeof(connerr);

                getsockopt(proxy->dst.fd, SOL_SOCKET, SO_ERROR, &connerr, &errlen);
                if (connerr != 0) {
                    SYNTAB_LOCK_WRITE();
                    destroy_proxy(proxy, args->epoll_fd);
                    SYNTAB_UNLOCK_WRITE();
                    break;
                }

                ret = pipe2(proxy->src.buf.fds, O_NONBLOCK);
                if (ret < 0) {
                    pep_error("Failed to allocate PEP IN buffer!");
                }

                ret = pipe2(proxy->dst.buf.fds, O_NONBLOCK);
                if (ret < 0) {
                    close(proxy->src.buf.in);
                    close(proxy->src.buf.out);
                    pep_error("Failed to allocate PEP OUT buffer!");
                }

                proxy->status = PST_OPEN;
                setup_socket(proxy->src.fd);
                setup_socket(proxy->dst.fd);
            }
            /* fall through */
            case PST_OPEN: {
                if (event->events & (EPOLLHUP | EPOLLERR)) {
                    if (proxy->enqueued) {
                        list_del(&proxy->qnode);
                    }

                    SYNTAB_LOCK_WRITE();
                    destroy_proxy(proxy, args->epoll_fd);
                    SYNTAB_UNLOCK_WRITE();
                    continue;
                }

                if (event->events & (EPOLLIN | EPOLLOUT)) {
                    list_add2tail(&local_list, &proxy->qnode);
                    num_works++;
                    proxy->enqueued = 1;
                }

                break;
            }
            default:
                break;
            }
        }
        if (list_is_empty(&local_list)) {
            continue;
        }

        /*
         * Now we're able to give connections with ready I/O status
         * to worker threads. Worker threads from PEPsal threads pool
         * will preform the I/O according to state of given connection
         * and move it back to the ready_queue when I/O job is finished.
         * Poller loop will wait until all connections it gave to worker
         * threads will be fully handled.
         */
        PEPQUEUE_LOCK(args->active_queue);
        pepqueue_enqueue_list(args->active_queue, &local_list, num_works);

        PEPQUEUE_LOCK(args->ready_queue);
        PEPQUEUE_WAKEUP_WAITERS(args->active_queue);
        PEPQUEUE_UNLOCK(args->active_queue);

        /* Wait until connections are fully handled */
        while (args->ready_queue->num_items != num_works) {
            PEPQUEUE_WAIT(args->ready_queue);
        }

        list_init_head(&local_list);
        pepqueue_dequeue_list(args->ready_queue, &local_list);
        PEPQUEUE_UNLOCK(args->ready_queue);

        /*
         * Now it's a time to handle connections after I/O is completed.
         * There are only two possible ways to do it:
         * 1) Close the connection if an I/O error occured or EOF was reached
         * 2) Continue work with connection and renew its I/O status
         */
        list_for_each_safe(&local_list, entry, safe)
        {
            proxy = list_entry(entry, struct pep_proxy, qnode);
            proxy->enqueued = 0;
            for (size_t i = 0; i < PROXY_ENDPOINTS; ++i) {
                endp = &proxy->endpoints[i];
                iostat = endp->iostat;
                if ((iostat & PEP_IOERR) || (iostat & PEP_IOEOF)) {
                    SYNTAB_LOCK_WRITE();
                    list_del(&proxy->qnode);
                    destroy_proxy(proxy, args->epoll_fd);
                    SYNTAB_UNLOCK_WRITE();
                    break;
                }

                endp->iostat &= ~(PEP_IOWDONE | PEP_IORDONE | PEP_IOEOF);
            }
        }
    }
}

void signal_new_connection_to_poller(pthread_t poller)
{
    if (pthread_kill(poller, POLLER_NEWCONN_SIG) != 0) {
        pep_error("Failed to send %d siganl to poller thread", POLLER_NEWCONN_SIG);
    }
}
