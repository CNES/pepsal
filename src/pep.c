/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005
 * Copyleft Dan Kruchining <dkruchinin@acm.com> 2010
 * Copyright CNES 2017
 * See AUTHORS and COPYING before using this software.
 *
 *
 *
 */

#define _GNU_SOURCE
#include "config.h"
#include "pepsal.h"
#include "pepqueue.h"
#include "syntab.h"

#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/user.h>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <getopt.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <sys/epoll.h>
#include <sys/resource.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>

#include <sys/time.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE (1 << 12)
#endif

/*
 * Data structure to fill with packet headers when we
 * get a new syn:
 *
 * struct ipv4_packet
 *      iph : ip header for the packet
 *      tcph: tcp header for the segment
 *
 */


static int DEBUG = 0;
static int background = 0;
static int gc_interval = PEP_GC_INTERVAL;
static int pending_conn_lifetime = PEP_PENDING_CONN_LIFETIME;
static int portnum = PEP_DEFAULT_PORT;
static int max_conns = (PEP_MIN_CONNS + PEP_MAX_CONNS) / 2;
static int ip_len = 40;
static char pepsal_ip_addr[40] = "::0";
static int snat = 0;
static char snat_addr[40] = "::0";


/*
* struct for tcp options
*/
static struct pep_sockopt sockopt;
/*
 * file descriptor for epoll
 */
int epoll_fd;

/*
 * PEP logger dumps all connections in the syn table to
 * the file specified by filename every PEPLOGGER_INTERVAL
 * seconds.
 */
struct pep_logger {
    FILE *file;
    timer_t timer;
    char *filename;
};

/*
 * Main queues for connections and work synchronization
 * active_queue is used to transfer read/write jobs to
 * worker threads from PEP threads pool. After all jobs in
 * active_queue are done, they're moved to the ready_queue
 * which is used by poller thread. After poller thread wakes up,
 * it cheks out all connections from ready_queue, checks theier status,
 * updates metainformation and restarts polling loop.
 */
static struct pep_queue active_queue, ready_queue;
static struct pep_logger logger;

static pthread_t listener;
static pthread_t poller;
static pthread_t timer_sch;
static pthread_t *workers = NULL;

#ifdef DISABLE_SYSLOG

#define pep_error(fmt, args...)                       \
    __pep_error(__FUNCTION__, __LINE__, fmt, ##args)  

#define pep_warning(fmt, args...)                     \
    __pep_warning(__FUNCTION__, __LINE__, fmt, ##args)

#define PEP_DEBUG(fmt, args...)                       \
    if (DEBUG) {                                      \
        fprintf(stderr, "[DEBUG] %s(): " fmt "\n",    \
                __FUNCTION__, ##args);                \
    }

#define PEP_DEBUG_DP(proxy, fmt, args...)                           \
    if (DEBUG) {                                                    \
        char __buf[40];                                             \
        toip6(__buf, (proxy)->src.addr);                            \
        fprintf(stderr, "[DEBUG] %s(): {%s:%d} " fmt "\n",          \
                __FUNCTION__, __buf, (proxy)->src.port, ##args);    \
    }
#else

#define pep_error(fmt, args...)                       \
    syslog(LOG_ERR, "%s():%d: " fmt " (errno %d)",    \
           __FUNCTION__, __LINE__, ##args, errno);    \
    __pep_error(__FUNCTION__, __LINE__, fmt, ##args)  

#define pep_warning(fmt, args...)                     \
    syslog(LOG_WARNING, "%s():%d: " fmt,              \
           __FUNCTION__, __LINE__, ##args);           \
    __pep_warning(__FUNCTION__, __LINE__, fmt, ##args)

#define PEP_DEBUG(fmt, args...)                       \
    if (DEBUG) {                                      \
        fprintf(stderr, "[DEBUG] %s(): " fmt "\n",    \
                __FUNCTION__, ##args);                \
        syslog(LOG_DEBUG, "%s(): " fmt, __FUNCTION__, \
              ##args);                                \
    }

#define PEP_DEBUG_DP(proxy, fmt, args...)                           \
    if (DEBUG) {                                                    \
        char __buf[40];                                             \
        toip6(__buf, (proxy)->src.addr);                            \
        fprintf(stderr, "[DEBUG] %s(): {%s:%d} " fmt "\n",          \
                __FUNCTION__, __buf, (proxy)->src.port, ##args);    \
        syslog(LOG_DEBUG, "%s(): {%s:%d} " fmt, __FUNCTION__,       \
               __buf, (proxy)->src.port, ##args);                   \
    }
#endif

#define TABLE_SIZE(_a) ((sizeof((_a)[0]))?sizeof(_a)/sizeof((_a)[0]):0)

static void __pep_error(const char *function, int line, const char *fmt, ...)
{
    va_list ap;
    char buf[PEP_ERRBUF_SZ];
    int err = errno;
    size_t len;

    va_start(ap, fmt);

    len = snprintf(buf, PEP_ERRBUF_SZ, "[ERROR]: ");
    len += vsnprintf(buf + len, PEP_ERRBUF_SZ - len, fmt, ap);
    if (err && (PEP_ERRBUF_SZ - len) > 1) {
        snprintf(buf + len, PEP_ERRBUF_SZ - len,
                 "\n      ERRNO: [%s:%d]", strerror(err), err);
    }

    fprintf(stderr, "%s\n         AT: %s:%d\n", buf, function, line);
    va_end(ap);
    closelog();
    exit(EXIT_FAILURE);
}

static void __pep_warning(const char *function, int line, const char *fmt, ...)
{
    va_list ap;
    char buf[PEP_ERRBUF_SZ];
    size_t len;

    va_start(ap, fmt);
    len = snprintf(buf, PEP_ERRBUF_SZ, "[WARNING]: ");
    if (PEP_ERRBUF_SZ - len > 1) {
        len += vsnprintf(buf + len, PEP_ERRBUF_SZ - len, fmt, ap);
    }

    fprintf(stderr, "%s\n       AT: %s:%d\n", buf, function, line);
    va_end(ap);
}

static void usage(char *name)
{
    fprintf(stderr,"Usage: %s [-V] [-h] [-v] [-d] [-f] [q] [n] [k]"
            " [-a address] [-p port]"
            " [-c max_conn] [-l logfile] [-t proxy_lifetime]"
            " [-g garbage collector interval]"
            " [-s source NAT address] [-T worker threads count]"
            " [-C congestion control algorithm]"
            " [-m TCP max segment size]\n", name);
    exit(EXIT_SUCCESS);
}

/*
 * Check if error @err is related to nonblocking I/O.
 * If it is in a set of nonblocking errors, it may handled
 * properly without program termination.
 */
static int nonblocking_err_p(int err)
{
    const int nb_errs[] = {
        EAGAIN,
        EINPROGRESS,
        EALREADY,
    };
    int i;

    for (i = 0; i < TABLE_SIZE(nb_errs); i++) {
        if (err == nb_errs[i])
            return 1;
    }

    return 0;
}

/*
 * Secure routine to translate a hex address in a
 * readable ip number:
 */

static void toip(char *ret, int address)
{
    int a,b,c,d;

    a = (0xFF000000 & address) >> 24;
    b = (0x00FF0000 & address) >> 16;
    c = (0x0000FF00 & address) >> 8;
    d = 0x000000FF & address;

    snprintf(ret,16,"%d.%d.%d.%d",a,b,c,d);
}

static void toip6(char *ret, uint16_t addr[8])
{

    snprintf(ret, 40, "%x:%x:%x:%x:%x:%x:%x:%x", 
                addr[0],addr[1],addr[2],addr[3],addr[4],addr[5],addr[6],addr[7]);
}

static char *conn_stat[] = {
    "PST_CLOSED",
    "PST_OPEN",
    "PST_CONNECT",
    "PST_PENDING",
};

static void logger_fn(void)
{
    struct pep_proxy *proxy;
    time_t tm;
    char ip_src[ip_len], ip_dst[ip_len], timebuf[128];
    int i = 1, len;

    PEP_DEBUG("Logger invoked!");
    SYNTAB_LOCK_READ();
    tm = time(NULL);
    ctime_r(&tm, timebuf);
    len = strlen(timebuf);
    timebuf[len - 1] = ']';
    fprintf(logger.file, "=== [%s ===\n", timebuf);
    syntab_foreach_connection(proxy) {
        toip6(ip_src, proxy->src.addr);
        toip6(ip_dst, proxy->dst.addr);
        fprintf(logger.file, "[%d] Proxy %s:%d <-> %s:%d\n", i++,
                ip_src, proxy->src.port, ip_dst, proxy->dst.port);
        fprintf(logger.file, "    Status: %s\n", conn_stat[proxy->status]);
        ctime_r(&proxy->syn_time, timebuf);
        fprintf(logger.file, "    SYN received: %s", timebuf);
        if (proxy->last_rxtx != 0) {
            ctime_r(&proxy->last_rxtx, timebuf);
            fprintf(logger.file, "    Last Rx/Tx activity: %s", timebuf);
        }

    }
    if (i == 1) {
        fprintf(logger.file, " No connections\n");
    }

    SYNTAB_UNLOCK_READ();
    fflush(logger.file);
}

static void setup_socket(int fd)
{
    struct timeval t= { 0, 10000 };
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(struct timeval));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(struct timeval));
    PEP_DEBUG("Socket %d: Setting up timeouts and syncronous mode.", fd);
}

#define ENDPOINT_EPOLLEVENTS (EPOLLIN | EPOLLHUP | EPOLLERR)
static struct pep_proxy *alloc_proxy(void)
{
    struct pep_proxy *proxy = calloc(1, sizeof(*proxy));
    int i;
    struct pep_endpoint *endp;

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
        endp->epoll_event.events = ENDPOINT_EPOLLEVENTS;
    }

    return proxy;
}

static void free_proxy(struct pep_proxy *proxy)
{
    assert(atomic_read(&proxy->refcnt) == 0);
    free(proxy);
}

static inline void pin_proxy(struct pep_proxy *proxy)
{
    atomic_inc(&proxy->refcnt);
}

static inline void unpin_proxy(struct pep_proxy *proxy)
{
    if (atomic_dec(&proxy->refcnt) == 1) {
        PEP_DEBUG_DP(proxy, "Free proxy");
        free_proxy(proxy);
    }
}

static void destroy_proxy(struct pep_proxy *proxy)
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
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL,
                      proxy->endpoints[i].fd,
                      &proxy->endpoints[i].epoll_event);
            close(proxy->endpoints[i].fd);
        }
        close(proxy->endpoints[i].buf.in);
        close(proxy->endpoints[i].buf.out);
    }

out:
    unpin_proxy(proxy);
}

/*
 * Garbage connections collector handler is periodically invoked
 * with gc_interval interval(in seconds) and cleans dead(or garbage)
 * connections.
 * When PEPsal catches SYN packet from the source endpoint,
 * it creates new pep_proxy instance, markes it with PST_PENDING status
 * and saves into the SYN table. After some time(actually after ACK is received)
 * this proxy shold be
 * activated, connection should be established and endpoints set up.
 * If everything is going alright, the proxy will be marked with PST_CONNECT
 * status. But the client might endup abnormally after SYN is sent. In this case
 * PEPsal has no chance to know about it. Thus PEPsal monitors all pending
 * connections in SYN table and closes them if a connection hasn't have any
 * activity for a long time.
 */
static void garbage_connections_collector(void)
{
    struct pep_proxy *proxy;
    struct list_node *item, *safe;
    time_t t_now, t_diff;

    PEP_DEBUG("Garbage connections collector activated!");

    SYNTAB_LOCK_WRITE();
    t_now = time(NULL);
    list_for_each_safe(&GET_SYNTAB()->conns, item, safe) {
        proxy = list_entry(item, struct pep_proxy, lnode);
        if (proxy->status != PST_PENDING) {
            continue;
        }

        t_diff = t_now - proxy->syn_time;
        if (t_diff >= pending_conn_lifetime) {
            PEP_DEBUG_DP(proxy, "Marked as garbage. Destroying...");
            destroy_proxy(proxy);
        }
    }

    SYNTAB_UNLOCK_WRITE();
}

static ssize_t pep_receive(struct pep_endpoint *endp)
{
    int iostat;
    ssize_t rb;

    if (endp->iostat & (PEP_IOERR | PEP_IOEOF)) {
        return 0;
    }

    rb = splice(endp->fd, NULL, endp->buf.in, NULL, PAGE_SIZE,
                SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK);

    if (rb < 0) {
        if (nonblocking_err_p(errno)) {
            endp->iostat |= PEP_IORDONE;
            return 0;
        }

        endp->iostat |= PEP_IOERR;
        return -1;
    }
    else if (rb == 0) {
        endp->iostat |= PEP_IOEOF;
        return 0;
    }
    return rb;
}

static ssize_t pep_send(struct pep_endpoint *from, int to_fd)
{
    ssize_t wb;

    if (from->iostat & (PEP_IOERR | PEP_IOWDONE)) {
        return 0;
    }

    wb = splice(from->buf.out, NULL, to_fd, NULL, PAGE_SIZE,
                SPLICE_F_MOVE | SPLICE_F_MORE| SPLICE_F_NONBLOCK);

    if (wb < 0) {
        if (nonblocking_err_p(errno)) {
            from->iostat |= PEP_IOWDONE;
            return 0;
        }

        from->iostat |= PEP_IOERR;
        return -1;
    }
    return wb;
}

static void pep_proxy_data(struct pep_endpoint *from, struct pep_endpoint *to)
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
    }
    else if (from->iostat & PEP_IORDONE) {
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

static int save_proxy_from_socket(struct sockaddr_in6 orig_dst, struct sockaddr_in6 cliaddr)
{
    char *buffer;
    struct pep_proxy *proxy, *dup;
    struct syntab_key key;
    int id = 0, ret, added = 0;

    PEP_DEBUG("Saving new SYN...");

    proxy = NULL;
    proxy = alloc_proxy();
    if (!proxy) {
        pep_warning("Failed to allocate new pep_proxy instance! [%s:%d]",
                    strerror(errno), errno);
        ret = -1;
        goto err;
    }

    /* Setup source and destination endpoints */
    for(int i=0 ; i<8; ++i){
             proxy->src.addr[i] = ntohs(cliaddr.sin6_addr.s6_addr16[i]);
        }
    for(int i=0 ; i<8; ++i){
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

    added = 1;
    PEP_DEBUG_DP(proxy, "Registered new SYN");
    if (ret < 0) {
        pep_warning("nfq_set_verdict to NF_ACCEPT failed! [%s:%d]",
                    strerror(errno), errno);
        goto err;
    }

    return ret;

err:
    if (added) {
        syntab_delete(proxy);
    }
    if (proxy != NULL) {
        unpin_proxy(proxy);
    }

    return ret;
}
void* edit_sockopts(struct pep_sockopt* socketopts){
    int ret,optval;
    SOCKOPT_LOCK();
    if (socketopts->fastopen){
        sockopt.fastopen = socketopts->fastopen;
    }
    if (socketopts->corck){
        sockopt.corck = socketopts->corck;
    }
    if (socketopts->nodelay){
        sockopt.nodelay = socketopts->nodelay;
    }
    if (socketopts->maxseg_size){
        sockopt.maxseg_size = socketopts->maxseg_size;
    }
    if (socketopts->congestion_algo != NULL && socketopts->congestion_algo[0] != '\0'){
        strcpy(sockopt.congestion_algo,socketopts->congestion_algo);
    }

    SOCKOPT_UNLOCK();
}
static void get_available_cc(char* cc_algorithm[20]) {
    FILE* file = fopen("/proc/sys/net/ipv4/tcp_available_congestion_control", "r");
    if (file == NULL) {
        pep_error("Failed to open /proc/sys/net/ipv4/tcp_available_congestion_control");
  
    }

    char buffer[256];
    int i = 0;  

    if (fgets(buffer, 256, file) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;
    } else {
        pep_error("Failed to read /proc/sys/net/ipv4/tcp_available_congestion_control");
    }
    const char * separators = " ";
    char * algo = strtok(buffer,separators);
    while (algo != NULL)
    {
        cc_algorithm[i] = algo;
        i++;
        algo = strtok ( NULL,separators);
    }
    
    fclose(file);
}

void *listener_loop(void UNUSED(*unused))
{
    int                  listenfd, optval, ret, connfd, out_fd,error;
    struct sockaddr_in   r_servaddr;
    struct sockaddr_in6  cliaddr, orig_dst, servaddr, r_servaddr6;
    int addrlen        = sizeof(orig_dst);
    char                 ipbuf[40],port_str [6];
    socklen_t            len;
    struct pep_proxy     *proxy;
    struct hostent       *host;
    struct addrinfo      hints, *host_res;
    unsigned short       r_port, c_port;
    struct syntab_key    key;
    struct pep_sockopt   socket_opts;

    listenfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (listenfd < 0) {
        pep_error("Failed to create listener socket!");
    }

    PEP_DEBUG("Opened listener socket: %d", listenfd);
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_addr = in6addr_any;
    servaddr.sin6_port = htons(portnum);
    optval = 1;
    ret = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                     &optval, sizeof(optval));
    if (ret < 0) {
        pep_error("Failed to set SOL_REUSEADDR option! [RET = %d]", ret);
    }
 
    /* Set socket transparent (able to bind to external address) */
    ret = setsockopt(listenfd, SOL_IP, IP_TRANSPARENT,
                     &optval, sizeof(optval));
    if (ret < 0) {
        pep_error("Failed to set IP_TRANSPARENT option! [RET = %d]", ret);
    }

    /* Set TCP_FASTOPEN socket option */
    SOCKOPT_LOCK();
    if (sockopt.fastopen) {
      optval = 5;
      ret = setsockopt(listenfd, SOL_TCP, TCP_FASTOPEN,
                       &optval, sizeof(optval));
      if (ret < 0) {
          pep_error("Failed to set TCP_FASTOPEN option! [RET = %d]", ret);
      }
    }
    SOCKOPT_UNLOCK();

    ret = bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (ret < 0) {
        pep_error("Failed to bind socket! [RET = %d]", ret);
    }

    ret = listen(listenfd, LISTENER_QUEUE_SIZE);
    if (ret < 0) {
        pep_error("Failed to set quesize of listenfd to %d! [RET = %d]",
                  LISTENER_QUEUE_SIZE, ret);
    }

    /* Accept loop */
    PEP_DEBUG("Entering lister main loop...");
    for (;;) {
        out_fd = -1;
        proxy = NULL;
        len = sizeof(struct sockaddr_in6);
        connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &len);
        if (connfd < 0) {
            pep_warning("accept() failed! [Errno: %s, %d]",
                        strerror(errno), errno);
            continue;
        }
        /* Socket is bound to original destination */
        if(getsockname(connfd, (struct sockaddr *) &orig_dst, &addrlen) < 0){
            pep_warning("Failed to get original dest from socket! [%s:%d]",
                        strerror(errno), errno);
            goto close_connection;
        }
        SOCKOPT_LOCK();
        memcpy(&socket_opts, &sockopt, sizeof(socket_opts));
        SOCKOPT_UNLOCK();
        /*
         * Try to find incomming connection in our SYN table
         * It must be already there waiting for activation.
         */
        for(int i=0 ; i<8; ++i){
            key.addr[i] = ntohs(cliaddr.sin6_addr.s6_addr16[i]);    
        }
        key.port = ntohs(cliaddr.sin6_port);
        #ifdef ENABLE_DST_IN_KEY
        key.dst_port = ntohs(orig_dst.sin6_port);
        for(int i=0 ; i<8; ++i){
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
        pin_proxy(proxy);
        assert(proxy->status == PST_PENDING);
        SYNTAB_UNLOCK_READ();

        r_port = proxy->dst.port;
        memset(&hints, 0,sizeof(hints));
        hints.ai_family = AF_UNSPEC ;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;        
        sprintf(port_str,"%d",r_port);   
        toip6(ipbuf, proxy->dst.addr);
        error = getaddrinfo(ipbuf,port_str,&hints,&host_res);
        if (error) {
            pep_warning("Failed to get host %s!", ipbuf);
            goto close_connection;
        }
        /* Check if received connexion is IPV6 or IPV4-mapped connexion*/
        int is_ipv4 = IN6_IS_ADDR_V4MAPPED(&cliaddr.sin6_addr);
        if (is_ipv4){
            memset(&r_servaddr, 0, sizeof(r_servaddr));
            r_servaddr.sin_addr.s_addr = ((struct sockaddr_in6 *)(host_res->ai_addr))->sin6_addr.s6_addr32[3];
            toip(ipbuf,ntohl(r_servaddr.sin_addr.s_addr));
            PEP_DEBUG("Connecting to %s:%d...", ipbuf, r_port);
            r_servaddr.sin_family = AF_INET;
            r_servaddr.sin_port = htons(r_port);
            ret = socket(AF_INET, SOCK_STREAM, 0);
        }
        else{ 
            PEP_DEBUG("Connecting to %s:%d...", ipbuf, r_port);
            memset(&r_servaddr6, 0, sizeof(r_servaddr6));       
            r_servaddr6.sin6_family = AF_INET6;
            r_servaddr6.sin6_addr = ((struct sockaddr_in6 *)(host_res->ai_addr))->sin6_addr;
            r_servaddr6.sin6_port = htons(r_port);
            ret = socket(AF_INET6, SOCK_STREAM, 0);
        }
        freeaddrinfo(host_res);
        if (ret < 0) {
            pep_warning("Failed to create socket! [%s:%d]",
                        strerror(errno), errno);
            goto close_connection;
        }
        out_fd = ret;
        fcntl(out_fd, F_SETFL, O_NONBLOCK);
        /*
         * Set outbound endpoint to transparent mode
         * (bind to external address)
         */
        ret = setsockopt(out_fd, SOL_IP, IP_TRANSPARENT,
                         &optval, sizeof(optval));
        if (ret < 0) {
            pep_error("Failed to set IP_TRANSPARENT option! [RET = %d]", ret);
        }
        optval = 64 * 1024;

        ret=setsockopt(out_fd, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
        if (ret == -1) {
            pep_error("Failed to set receiv buffer size option! [RET = %d]", ret);
        }

        if (!snat)
            toip6(ipbuf, proxy->src.addr);
        else
            strncpy(ipbuf, snat_addr, sizeof(ipbuf)-1);

        if (socket_opts.quickack) {
            optval = 1;
            ret = setsockopt(out_fd, IPPROTO_TCP,TCP_QUICKACK,&optval, sizeof(optval));
            if (ret < 0) {
                pep_error("Failed to set TCP QUICACK option! [RET = %d]", ret);
            }
        }
        if (socket_opts.nodelay) {
            optval = 1;
            ret = setsockopt(out_fd, IPPROTO_TCP, TCP_NODELAY,&optval, sizeof(optval));
            if (ret < 0) {
                pep_error("Failed to set TCP NODELAY option! [RET = %d]", ret);
            }
        }
        if (socket_opts.corck) {
            optval = 1;
            ret = setsockopt(out_fd, IPPROTO_TCP, TCP_CORK,&optval,sizeof(optval));
            if (ret < 0){
                pep_error("Failed to set TCP CORCK option! [RET = %d]",ret);
            }
        }
        if (socket_opts.maxseg_size){
            optval = sockopt.maxseg_size;
            ret = setsockopt(out_fd, IPPROTO_TCP, TCP_MAXSEG, &optval,sizeof(optval));
            if (ret < 0) {
                pep_error("Failed to set TCP MSS option! [RET = %d]", ret);
            }
        }
        if (socket_opts.congestion_algo != NULL && sockopt.congestion_algo[0] != '\0'){
            socklen_t len = strlen(sockopt.congestion_algo);
            ret = setsockopt(out_fd, IPPROTO_TCP, TCP_CONGESTION, &sockopt.congestion_algo,len);
            if (ret < 0) {
                pep_error("Failed to set TCP Congestion Control algorithm! [RET = %d]", ret);
            }
        }
        if (socket_opts.fastopen) {
            ret = splice(proxy->src.buf.out, NULL, out_fd, NULL, PAGE_SIZE,
                         SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK);
        }
        else {
            if(is_ipv4){
                ret = connect(out_fd, (struct sockaddr *)&r_servaddr,
                        sizeof(r_servaddr));
            }
            else{
                ret = connect(out_fd, (struct sockaddr *)&r_servaddr6,
                        sizeof(r_servaddr6));
            }
        }
        if ((ret < 0) && !nonblocking_err_p(errno)) {
            pep_warning("Failed to connect! [%s:%d]", strerror(errno), errno);
            goto close_connection;
        }

        proxy->src.fd = connfd;
        ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connfd, &proxy->src.epoll_event);
        if (ret < 0) {
            pep_error("epoll_ctl [%s:%d]", strerror(errno), errno);
            goto close_connection;
        }

        proxy->dst.fd = out_fd;
        ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, out_fd, &proxy->dst.epoll_event);
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
        if (pthread_kill(poller, POLLER_NEWCONN_SIG) != 0) {
            pep_error("Failed to send %d siganl to poller thread",
                      POLLER_NEWCONN_SIG);
        }

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
        }
        if (proxy) {
            destroy_proxy(proxy);
        }
    }

    /* Normally this code won't be executed */
    PEP_DEBUG("Exiting...");
    pthread_exit(NULL);
}

/* An empty signal handler. It only needed to interrupt poll() */
static void poller_sighandler(int signo)
{
    PEP_DEBUG("Received signal %d", signo);
}

static void *poller_loop(void  __attribute__((unused)) *unused)
{
    int                 epollret, num_works, i, num_clients, iostat;
    struct pep_proxy    *proxy;
    struct pep_endpoint *endp, *target;
    struct epoll_event  *event, events[2 * max_conns];
    struct list_node    *entry, *safe;
    struct list_head    local_list;
    sigset_t            sigset;
    struct sigaction    sa;

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

        epollret = epoll_wait(epoll_fd, events, 2 * max_conns, -1);
        if (epollret < 0) {
            if (errno == EINTR) {
                /* It seems that new client just appered. Renew descriptors. */
                continue;
            }

            pep_error("poll() error!");
        }
        else if (epollret == 0) {
            continue;
        }

        num_works = 0;
        for (i = 0; i < epollret; i++) {
            event = &events[i];
            endp = (struct pep_endpoint *) event->data.ptr;
            proxy = (struct pep_proxy *) endp->owner;

            if (!event->events) {
                continue;
            }

            if (proxy->enqueued) {
                continue;
            }

            switch (proxy->status) {
                case PST_CONNECT:
                {
                    int ret, connerr, errlen = sizeof(int);

                    getsockopt(proxy->dst.fd, SOL_SOCKET, SO_ERROR,
                               &connerr, &errlen);
                    if (connerr != 0) {
                        destroy_proxy(proxy);
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
                case PST_OPEN:
                {
                    if (event->events & (EPOLLHUP | EPOLLERR)) {
                        if (proxy->enqueued) {
                            list_del(&proxy->qnode);
                        }

                        destroy_proxy(proxy);
                        continue;
                    }

                    if (event->events & (EPOLLIN | EPOLLOUT)) {
                        list_add2tail(&local_list, &proxy->qnode);
                        num_works++;
                        proxy->enqueued = 1;
                    }

                    break;
                }
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
        PEPQUEUE_LOCK(&active_queue);
        pepqueue_enqueue_list(&active_queue, &local_list, num_works);

        PEPQUEUE_LOCK(&ready_queue);
        PEPQUEUE_WAKEUP_WAITERS(&active_queue);
        PEPQUEUE_UNLOCK(&active_queue);

        /* Wait until connections are fully handled */
        while (ready_queue.num_items != num_works) {
            PEPQUEUE_WAIT(&ready_queue);
        }

        list_init_head(&local_list);
        pepqueue_dequeue_list(&ready_queue, &local_list);
        PEPQUEUE_UNLOCK(&ready_queue);

        /*
         * Now it's a time to handle connections after I/O is completed.
         * There are only two possible ways to do it:
         * 1) Close the connection if an I/O error occured or EOF was reached
         * 2) Continue work with connection and renew its I/O status
         */
        list_for_each_safe(&local_list, entry, safe) {
            proxy = list_entry(entry, struct pep_proxy, qnode);
            proxy->enqueued = 0;
            for (i = 0; i < PROXY_ENDPOINTS; i++) {
                endp = &proxy->endpoints[i];
                iostat = endp->iostat;
                if ((iostat & PEP_IOERR) ||
                    (iostat & PEP_IOEOF)) {
                    list_del(&proxy->qnode);
                    destroy_proxy(proxy);
                    break;
                }

                endp->iostat &= ~(PEP_IOWDONE | PEP_IORDONE | PEP_IOEOF);
            }
        }
    }
}

static void *workers_loop(void __attribute__((unused)) *unused)
{
    struct pep_proxy *proxy;
    struct list_head local_list;
    int ret, ready_items;

    PEPQUEUE_LOCK(&active_queue);
    for (;;) {
        list_init_head(&local_list);
        ready_items = 0;
        PEPQUEUE_WAIT(&active_queue);

        while (active_queue.num_items > 0) {
            proxy = pepqueue_dequeue(&active_queue);
            PEPQUEUE_UNLOCK(&active_queue);

            pep_proxy_data(&proxy->src, &proxy->dst);
            pep_proxy_data(&proxy->dst, &proxy->src);

            proxy->last_rxtx = time(NULL);
            list_add2tail(&local_list, &proxy->qnode);
            ready_items++;

            PEPQUEUE_LOCK(&active_queue);
        }

        PEPQUEUE_LOCK(&ready_queue);
        pepqueue_enqueue_list(&ready_queue, &local_list, ready_items);
        PEPQUEUE_UNLOCK(&ready_queue);
        PEPQUEUE_WAKEUP_WAITERS(&ready_queue);
    }
}

static void *timer_sch_loop(void __attribute__((unused)) *unused)
{
    struct timeval last_log_evt_time = {0U, 0U}, last_gc_evt_time = {0U, 0U}, now;

    if (logger.filename) {
        PEP_DEBUG("Setting up PEP logger");
        logger.file = fopen(logger.filename, "w+");
        if (!logger.file) {
            pep_error("Failed to open log file %s!", logger.filename);
        }
        gettimeofday(&last_log_evt_time, 0);
        gettimeofday(&last_gc_evt_time, 0);
    }
    
    for(;;) { 
        gettimeofday(&now, 0);
        if (logger.file && now.tv_sec > last_log_evt_time.tv_sec + PEPLOGGER_INTERVAL) {
            logger_fn();
            gettimeofday(&last_log_evt_time, 0);
        }

        if (now.tv_sec > last_gc_evt_time.tv_sec + gc_interval) {
            garbage_connections_collector();
            gettimeofday(&last_gc_evt_time, 0);
        }
        sleep(2);
    }
}

static void init_pep_threads(void)
{
    int ret;
    PEP_DEBUG("Creating listener thread");
    ret = pthread_create(&listener, NULL, listener_loop, NULL);
    if (ret) {
        pep_error("Failed to create the listener thread! [RET = %d]", ret);
    }

    PEP_DEBUG("Creating poller thread");
    ret = pthread_create(&poller, NULL, poller_loop, NULL);
    if (ret < 0) {
        pep_error("Failed to create the poller thread! [RET = %d]", ret);
    }
    PEP_DEBUG("Creating timer_sch thread");
    ret = pthread_create(&timer_sch, NULL, timer_sch_loop, NULL);
    if (ret < 0) {
        pep_error("Failed to create the timer_sch thread! [RET = %d]", ret);
    }
    
}

static void init_pep_queues(void)
{
    PEP_DEBUG("Initialize PEP queue for active connections...");
    pepqueue_init(&active_queue);

    PEP_DEBUG("Initialize PEP queue for handled connections...");
    pepqueue_init(&ready_queue);
}

static void create_threads_pool(int num_threads)
{
    int ret, i;

    workers = calloc(num_threads, sizeof(pthread_t));
    if (!workers) {
        pep_error("Failed to create threads pool of %d threads!",
                  num_threads);
    }
    for (i = 0; i < num_threads; i++) {
        ret = pthread_create(&workers[i], NULL,
                             workers_loop, NULL);
        if (ret) {
            pep_error("Failed to create %d thread in pool!", i + 1);
        }
    }
}

int main(int argc, char *argv[])
{
    int c, ret, numfds, peppool_threads = PEPPOOL_THREADS;
    struct rlimit lim,new_lim;
    void *valptr;
    sigset_t sigset;
    char* cc_algorithm[20];
    SOCKOPT_INIT_LOCK();
    memset(&sockopt, 0, sizeof(sockopt));
    memset(&logger, 0, sizeof(logger));
    get_available_cc(cc_algorithm);
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"daemon", 1, 0, 'd'},
            {"verbose", 1, 0, 'v'},
            {"help", 0, 0, 'h'},
            {"fastopen", 0, 0, 'f'},
            {"port", 1, 0, 'p'},
            {"version", 0, 0, 'V'},
            {"address", 1, 0, 'a'},
            {"logfile", 1, 0, 'l'},
            {"gc_interval", 1, 0, 'g'},
            {"plifetime", 1, 0,'t'},
            {"conns", 1, 0, 'c'},
            {"snat", 1, 0, 's'},
            {"threads", 1, 0, 'T'},
            {"quickack",0, 0, 'q'},
            {"nodelay",0, 0, 'n'},
            {"corck",0, 0, 'k'},
            {"congestion_algo",0, 0, 'C'},
            {"max_segment_size",0, 0, 'm'},
            {0, },
        };

        c = getopt_long(argc, argv, "dvVhfqnkp:a:l:g:t:c:s:T:C:m:",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'd':
                background = 1;
                break;
            case 'v':
                DEBUG = 1;
                break;
            case 'h':
                usage(argv[0]); //implies exit
                break;
            case 'f':
                sockopt.fastopen = 1;
                break;
            case 'p':
                portnum = atoi(optarg);
                break;
            case 'a':
                strncpy(pepsal_ip_addr, optarg, 40);
                break;
            case 'l':
                logger.filename = optarg;
                break;
            case 't':
                pending_conn_lifetime = atoi(optarg);
                break;
            case 'g':
                gc_interval = atoi(optarg);
                break;
            case 'c':
                max_conns = atoi(optarg);
                if ((max_conns < PEP_MIN_CONNS) ||
                    (max_conns > PEP_MAX_CONNS)) {
                    usage(argv[0]);
                }

                break;
            case 's':
                snat = 1;
                strncpy(snat_addr, optarg, 40);
                break;
            case 'T':
                peppool_threads = atoi(optarg);
                break;
            case 'q':
                sockopt.quickack = 1;
                break;
            case 'n':
                sockopt.nodelay = 1;
                break;
            case 'k':
                sockopt.corck = 1;
                break;
            case 'C':  
                strncpy(sockopt.congestion_algo, optarg, 10);
                int is_algorithm_found;
                for (size_t i =0;i<20;i++){
                    if (strcmp(sockopt.congestion_algo,cc_algorithm[i]) == 0){
                        is_algorithm_found = 1;
                        break;
                    }
                }
                if(!is_algorithm_found){
                fprintf(stderr,"Requested congestion control algorithm is not available on the system \n");
                usage(argv[0]);
                }
                break;
            case 'm':
                sockopt.maxseg_size = atoi(optarg);
                break;
            case 'V':
                printf("PEPSal ver. %s\n", VERSION);
                exit(0);
        }
    }
    openlog(PROGRAM_NAME, LOG_PID, LOG_DAEMON);

    /*setting new ressources limit*/
    new_lim.rlim_cur = (4 * max_conns);
    new_lim.rlim_max = 1048576;
    if (setrlimit(RLIMIT_NOFILE,&new_lim) ==  -1){
        pep_error("Failed to set new ressources limits");

    }
    
    if (background) {
        PEP_DEBUG("Daemonizing...");
        if (daemon(0, 1) < 0) {
            pep_error("daemon() failed!");
        }
    }

    PEP_DEBUG("Init SYN table with %d max connections", max_conns);
    ret = syntab_init(max_conns);
    if (ret < 0) {
        pep_error("Failed to initialize SYN table!");
    }

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);

    sigemptyset(&sigset);
    sigaddset(&sigset, POLLER_NEWCONN_SIG);
    sigaddset(&sigset, SIGPIPE);
    sigprocmask(SIG_BLOCK, &sigset, NULL);

    init_pep_queues();
    init_pep_threads();
    create_threads_pool(peppool_threads);

    PEP_DEBUG("Pepsal started...");
    pthread_join(listener, &valptr);
    pthread_join(poller, &valptr);
    pthread_join(timer_sch, &valptr);
    PEP_DEBUG("exiting...\n");
    SOCKOPT_DESTROY_LOCK();
    close(epoll_fd);
    closelog();
    return 0;
}
