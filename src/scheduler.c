#include "scheduler.h"
#include "log.h"
#include "pepdefs.h"
#include "syntab.h"

#include <string.h>
#include <sys/time.h>
#include <unistd.h>

static char* conn_stat[] = {
    "PST_CLOSED",
    "PST_OPEN",
    "PST_CONNECT",
    "PST_PENDING",
};

static inline void
logger_fn(FILE* logger)
{
    struct pep_proxy* proxy;
    time_t tm;
    char ip_src[IP_ADDR_LEN], ip_dst[IP_ADDR_LEN], timebuf[128];
    int i = 0, len;

    PEP_DEBUG("Logger invoked!");
    SYNTAB_LOCK_READ();
    tm = time(NULL);
    ctime_r(&tm, timebuf);
    len = strlen(timebuf);
    timebuf[len - 1] = ']';
    fprintf(logger, "=== [%s ===\n", timebuf);
    syntab_foreach_connection(proxy)
    {
        toip6(ip_src, proxy->src.addr);
        toip6(ip_dst, proxy->dst.addr);
        fprintf(logger,
            "[%d] Proxy %s:%d <-> %s:%d\n",
            ++i,
            ip_src,
            proxy->src.port,
            ip_dst,
            proxy->dst.port);
        fprintf(logger, "    Status: %s\n", conn_stat[proxy->status]);
        ctime_r(&proxy->syn_time, timebuf);
        fprintf(logger, "    SYN received: %s", timebuf);
        if (proxy->last_rxtx != 0) {
            ctime_r(&proxy->last_rxtx, timebuf);
            fprintf(logger, "    Last Rx/Tx activity: %s", timebuf);
        }
    }
    if (i == 0) {
        fprintf(logger, " No connections\n");
    }

    SYNTAB_UNLOCK_READ();
    fflush(logger);
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
static inline void
garbage_connections_collector(int pending_conn_lifetime, int epoll_fd)
{
    struct pep_proxy* proxy;
    struct list_node *item, *safe;
    time_t t_now, t_diff;

    PEP_DEBUG("Garbage connections collector activated!");

    SYNTAB_LOCK_WRITE();
    t_now = time(NULL);
    list_for_each_safe(&GET_SYNTAB()->conns, item, safe)
    {
        proxy = list_entry(item, struct pep_proxy, lnode);
        if (proxy->status != PST_PENDING) {
            continue;
        }

        t_diff = t_now - proxy->syn_time;
        if (t_diff >= pending_conn_lifetime) {
            PEP_DEBUG_DP(proxy, "Marked as garbage. Destroying...");
            destroy_proxy(proxy, epoll_fd);
        }
    }

    SYNTAB_UNLOCK_WRITE();
}

void* timer_sch_loop(void* arg)
{
    struct scheduler_thread_arguments* args = (struct scheduler_thread_arguments*)arg;
    struct timeval last_log_evt_time = { 0U, 0U },
                   last_gc_evt_time = { 0U, 0U },
                   now;

    FILE* logger;
    if (args->logger_filename) {
        PEP_DEBUG("Setting up PEP logger");
        logger = fopen(args->logger_filename, "w+");
        if (!logger) {
            pep_error("Failed to open log file %s!", args->logger_filename);
        }
        gettimeofday(&last_log_evt_time, 0);
        gettimeofday(&last_gc_evt_time, 0);
    }

    for (;;) {
        gettimeofday(&now, 0);
        if (logger && now.tv_sec > last_log_evt_time.tv_sec + PEPLOGGER_INTERVAL) {
            logger_fn(logger);
            gettimeofday(&last_log_evt_time, 0);
        }

        if (now.tv_sec > last_gc_evt_time.tv_sec + args->gc_interval) {
            garbage_connections_collector(args->pending_conn_lifetime, args->epoll_fd);
            gettimeofday(&last_gc_evt_time, 0);
        }
        sleep(2);
    }
}
