#define _GNU_SOURCE
#include "listener.h"
#include "conntrack.h"
#include "log.h"
#include "pepdefs.h"
#include "pepsal.h"
#include "poller.h"
#include "sockoptions.h"
#include "syntab.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

static inline void
unpin_proxy(struct pep_proxy* proxy)
{
    if (atomic_dec(&proxy->refcnt) == 1) {
        PEP_DEBUG_DP(proxy, "Free proxy");
        assert(atomic_read(&proxy->refcnt) == 0);
        free(proxy);
    }
}

static int
save_proxy_from_socket(struct sockaddr_in6 orig_dst,
    struct sockaddr_in6 cliaddr)
{
    char* buffer;
    struct pep_proxy* dup;
    struct syntab_key key;
    int id = 0, ret;

    PEP_DEBUG("Saving new SYN...");

    struct pep_proxy* proxy = alloc_proxy();
    if (!proxy) {
        pep_warning("Failed to allocate new pep_proxy instance! [%s:%d]",
            strerror(errno),
            errno);
        ret = -1;
        goto err;
    }

    /* Setup source and destination endpoints */
    for (int i = 0; i < 8; ++i) {
        proxy->src.addr[i] = ntohs(cliaddr.sin6_addr.s6_addr16[i]);
    }
    for (int i = 0; i < 8; ++i) {
        proxy->dst.addr[i] = ntohs(orig_dst.sin6_addr.s6_addr16[i]);
    }
    proxy->src.port = ntohs(cliaddr.sin6_port);
    proxy->dst.port = ntohs(orig_dst.sin6_port);
    proxy->syn_time = time(NULL);
    syntab_format_key(proxy, &key);

    /* Check for duplicate syn, and drop it.
     * This happens when RTT is too long and we
     * still didn't establish the connection.
     */
    SYNTAB_LOCK_WRITE();
    dup = syntab_find(&key);
    if (dup != NULL) {
        PEP_DEBUG_DP(dup, "Duplicate SYN. Dropping...");
        SYNTAB_UNLOCK_WRITE();
        goto err;
    }

    /* add to the table... */
    proxy->status = PST_PENDING;
    ret = syntab_add(proxy);
    SYNTAB_UNLOCK_WRITE();
    if (ret < 0) {
        pep_warning("Failed to insert pep_proxy into a hash table!");
        goto err;
    }

    return ret;

err:
    if (proxy != NULL) {
        unpin_proxy(proxy);
    }

    return ret;
}

static int
configure_dest_socket(int socket_fd)
{
    int optval;
    struct pep_sockopt socket_opts;
    sockopt_read(&socket_opts);

    if (fcntl(socket_fd, F_SETFL, O_NONBLOCK) == -1) {
        pep_warning("Failed to set non-blocking socket! [%s:%d]", strerror(errno), errno);
        return -1;
    }

    /*
     * Set outbound endpoint to transparent mode (bind to external address)
     */
    optval = 1;
    if (setsockopt(socket_fd, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval)) == -1) {
        pep_warning("Failed to set IP_TRANSPARENT option! [%s:%d]", strerror(errno), errno);
        return -1;
    }

    optval = 64 * 1024;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval)) == -1) {
        pep_warning("Failed to set receiv buffer size option! [%s:%d]", strerror(errno), errno);
        return -1;
    }

    if (socket_opts.quickack) {
        optval = 1;
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_QUICKACK, &optval, sizeof(optval)) == -1) {
            pep_error("Failed to set TCP QUICACK option! [%s:%d]", strerror(errno), errno);
            return -1;
        }
    }

    if (socket_opts.nodelay) {
        optval = 1;
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) == -1) {
            pep_error("Failed to set TCP NODELAY option! [%s:%d]", strerror(errno), errno);
            return -1;
        }
    }

    if (socket_opts.corck) {
        optval = 1;
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_CORK, &optval, sizeof(optval)) == -1) {
            pep_error("Failed to set TCP CORCK option! [%s:%d]", strerror(errno), errno);
            return -1;
        }
    }

    if (socket_opts.maxseg_size) {
        optval = socket_opts.maxseg_size;
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_MAXSEG, &optval, sizeof(optval)) == -1) {
            pep_error("Failed to set TCP MSS option! [%s:%d]", strerror(errno), errno);
            return -1;
        }
    }

    if (socket_opts.congestion_algo != NULL && socket_opts.congestion_algo[0] != '\0') {
        socklen_t len = strlen(socket_opts.congestion_algo);
        if (setsockopt(socket_fd, IPPROTO_TCP, TCP_CONGESTION, &socket_opts.congestion_algo, len) == -1) {
            pep_error("Failed to set TCP Congestion Control algorithm! [%s:%d]", strerror(errno), errno);
            return -1;
        }
    }

    return 0;
}

void* listener_loop(void* arg)
{
    struct listener_thread_arguments* args = (struct listener_thread_arguments*)arg;
    int listenfd, optval, ret, connfd, out_fd, error;
    struct sockaddr_in r_servaddr;
    struct sockaddr_in6 cliaddr, orig_dst, servaddr, r_servaddr6;
    int addrlen = sizeof(orig_dst);
    char ipbuf[IP_ADDR_LEN], port_str[6];
    socklen_t len;
    struct pep_proxy* proxy;
    struct hostent* host;
    struct addrinfo hints, *host_res;
    unsigned short r_port, c_port;
    struct syntab_key key;

    listenfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (listenfd < 0) {
        pep_error("Failed to create listener socket!");
    }

    PEP_DEBUG("Opened listener socket: %d", listenfd);
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_addr = in6addr_any;
    servaddr.sin6_port = htons(args->port_number);
    optval = 1;
    ret = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (ret < 0) {
        pep_error("Failed to set SOL_REUSEADDR option! [RET = %d]", ret);
    }

    /* Set socket transparent (able to bind to external address) */
    ret = setsockopt(listenfd, SOL_IP, IP_TRANSPARENT, &optval, sizeof(optval));
    if (ret < 0) {
        pep_error("Failed to set IP_TRANSPARENT option! [RET = %d]", ret);
    }

    /* Set TCP_FASTOPEN socket option */
    if (sockopt_is_fastopen()) {
        optval = 5;
        ret = setsockopt(listenfd, SOL_TCP, TCP_FASTOPEN, &optval, sizeof(optval));
        if (ret < 0) {
            pep_error("Failed to set TCP_FASTOPEN option! [RET = %d]", ret);
        }
    }

    ret = bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    if (ret < 0) {
        pep_error("Failed to bind socket! [RET = %d]", ret);
    }

    ret = listen(listenfd, LISTENER_QUEUE_SIZE);
    if (ret < 0) {
        pep_error("Failed to set quesize of listenfd to %d! [RET = %d]",
            LISTENER_QUEUE_SIZE,
            ret);
    }

    /* Accept loop */
    PEP_DEBUG("Entering lister main loop...");
    for (;;) {
        out_fd = -1;
        proxy = NULL;
        len = sizeof(struct sockaddr_in6);
        connfd = accept(listenfd, (struct sockaddr*)&cliaddr, &len);
        if (connfd < 0) {
            pep_warning("accept() failed! [Errno: %s, %d]", strerror(errno), errno);
            continue;
        }
        /* Socket is bound to original destination */
        if (getsockname(connfd, (struct sockaddr*)&orig_dst, &addrlen) < 0) {
            pep_warning("Failed to get original dest from socket! [%s:%d]",
                strerror(errno),
                errno);
            goto close_connection;
        }
        /*
         * Try to find incomming connection in our SYN table
         * It must be already there waiting for activation.
         */
        for (int i = 0; i < 8; ++i) {
            key.addr[i] = ntohs(cliaddr.sin6_addr.s6_addr16[i]);
        }
        key.port = ntohs(cliaddr.sin6_port);
#ifdef ENABLE_DST_IN_KEY
        key.dst_port = ntohs(orig_dst.sin6_port);
        for (int i = 0; i < 8; ++i) {
            key.dst_addr[i] = ntohs(orig_dst.sin6_addr.s6_addr16[i]);
        }
#endif
        toip6(ipbuf, key.addr);
        PEP_DEBUG("New incomming connection from: %s:%d ", ipbuf, key.port);

        SYNTAB_LOCK_READ();
        proxy = syntab_find(&key);

        /*
         * If the proxy is not in the table, add the entry.
         */
        if (!proxy) {
            SYNTAB_UNLOCK_READ();
            save_proxy_from_socket(orig_dst, cliaddr);
            SYNTAB_LOCK_READ();
            proxy = syntab_find(&key);
        }
        /*
         * If still can't find key in the table, there is an error.
         */
        if (!proxy) {
            pep_warning("Can not find the connection in SYN table. "
                        "Terminating!");
            SYNTAB_UNLOCK_READ();
            goto close_connection;
        }

        /*
         * The proxy we fetched from the SYN table is in PST_PENDING state.
         * Now we're going to setup connection for it and configure endpoints.
         * While the proxy is in PST_PENDING state it may be possibly removed
         * by the garbage connections collector. Collector is invoked every N
         * seconds and removes from SYN table all pending connections
         * that were not activated during predefined interval. Thus we have
         * to pin our proxy to protect ourself from segfault.
         */
        atomic_inc(&proxy->refcnt);
        assert(proxy->status == PST_PENDING);
        SYNTAB_UNLOCK_READ();

        r_port = proxy->dst.port;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        sprintf(port_str, "%d", r_port);
        toip6(ipbuf, proxy->dst.addr);
        error = getaddrinfo(ipbuf, port_str, &hints, &host_res);
        if (error) {
            pep_warning("Failed to get host %s!", ipbuf);
            goto close_connection;
        }
        /* Check if received connexion is IPV6 or IPV4-mapped connexion*/
        int is_ipv4 = IN6_IS_ADDR_V4MAPPED(&cliaddr.sin6_addr);
        if (is_ipv4) {
            memset(&r_servaddr, 0, sizeof(r_servaddr));
            r_servaddr.sin_addr.s_addr = ((struct sockaddr_in6*)(host_res->ai_addr))->sin6_addr.s6_addr32[3];
            toip(ipbuf, ntohl(r_servaddr.sin_addr.s_addr));
            PEP_DEBUG("Connecting to %s:%d...", ipbuf, r_port);
            r_servaddr.sin_family = AF_INET;
            r_servaddr.sin_port = htons(r_port);
            out_fd = socket(AF_INET, SOCK_STREAM, 0);
        } else {
            PEP_DEBUG("Connecting to %s:%d...", ipbuf, r_port);
            memset(&r_servaddr6, 0, sizeof(r_servaddr6));
            r_servaddr6.sin6_family = AF_INET6;
            r_servaddr6.sin6_addr = ((struct sockaddr_in6*)(host_res->ai_addr))->sin6_addr;
            r_servaddr6.sin6_port = htons(r_port);
            out_fd = socket(AF_INET6, SOCK_STREAM, 0);
        }
        freeaddrinfo(host_res);
        if (out_fd < 0) {
            pep_warning("Failed to create socket! [%s:%d]", strerror(errno), errno);
            goto close_connection;
        }

        increase_connection_count();
        if (configure_dest_socket(out_fd) < 0) {
            goto close_connection;
        }

        if (sockopt_is_fastopen()) {
            ret = splice(proxy->src.buf.out,
                NULL,
                out_fd,
                NULL,
                PAGE_SIZE,
                SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK);
        } else {
            if (is_ipv4) {
                ret = connect(out_fd, (struct sockaddr*)&r_servaddr, sizeof(r_servaddr));
            } else {
                ret = connect(out_fd, (struct sockaddr*)&r_servaddr6, sizeof(r_servaddr6));
            }
        }
        if ((ret < 0) && !nonblocking_err_p()) {
            pep_warning("Failed to connect! [%s:%d]", strerror(errno), errno);
            goto close_connection;
        }

        proxy->src.fd = connfd;
        ret = epoll_ctl(args->epoll_fd, EPOLL_CTL_ADD, connfd, &proxy->src.epoll_event);
        if (ret < 0) {
            pep_error("epoll_ctl [%s:%d]", strerror(errno), errno);
            goto close_connection;
        }

        proxy->dst.fd = out_fd;
        ret = epoll_ctl(args->epoll_fd, EPOLL_CTL_ADD, out_fd, &proxy->dst.epoll_event);
        if (ret < 0) {
            pep_error("epoll_ctl [%s:%d]", strerror(errno), errno);
            goto close_connection;
        }

        if (proxy->status == PST_CLOSED) {
            unpin_proxy(proxy);
            goto close_connection;
        }

        proxy->status = PST_CONNECT;
        unpin_proxy(proxy);
        PEP_DEBUG("Sending signal to poller [%d, %d]!", connfd, out_fd);
        signal_new_connection_to_poller(args->poller);

        continue;

    close_connection:
        /*
         * Ok. Some error occured and we have to properly cleanup
         * all resources. Client socket must be closed and server
         * socket (if any) as well. Also it would be good if we
         * remove pep_proxy instance which caused an error from SYN
         * table.
         */

        close(connfd);
        if (out_fd >= 0) {
            close(out_fd);
            decrease_connection_count();
        }
        if (proxy) {
            destroy_proxy(proxy, args->epoll_fd);
        }
    }

    /* Normally this code won't be executed */
    PEP_DEBUG("Exiting...");
    pthread_exit(NULL);
}
