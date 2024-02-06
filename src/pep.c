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

#include "conntrack.h"
#include "listener.h"
#include "log.h"
#include "pepqueue.h"
#include "poller.h"
#include "scheduler.h"
#include "sockoptions.h"
#include "syntab.h"
#include "workers.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <getopt.h>

static void
usage(char* name)
{
    fprintf(stderr,
        "Usage: %s [-V] [-h] [-v] [-d] [-f] [q] [n] [k]"
        " [-p port] [-c max_conn]"
        " [-l logfile] [-t proxy_lifetime]"
        " [-g garbage collector interval]"
        " [-T worker threads count]"
        " [-C congestion control algorithm]"
        " [-m TCP max segment size]\n",
        name);
    exit(EXIT_SUCCESS);
}

static inline void
serve_forever(int num_threads,
    struct listener_thread_arguments* lst_args,
    struct poller_thread_arguments* poll_args,
    struct scheduler_thread_arguments* sch_args,
    struct worker_thread_arguments* wkr_args)
{
    int ret;
    pthread_t listener, poller, timer_sch, *workers;

    PEP_DEBUG("Creating poller thread");
    ret = pthread_create(&poller, NULL, poller_loop, poll_args);
    if (ret != 0) {
        pep_error("Failed to create the poller thread! [RET = %d]", ret);
    }

    lst_args->poller = poller;
    PEP_DEBUG("Creating listener thread");
    ret = pthread_create(&listener, NULL, listener_loop, lst_args);
    if (ret != 0) {
        pep_error("Failed to create the listener thread! [RET = %d]", ret);
    }

    PEP_DEBUG("Creating timer_sch thread");
    ret = pthread_create(&timer_sch, NULL, timer_sch_loop, sch_args);
    if (ret != 0) {
        pep_error("Failed to create the timer_sch thread! [RET = %d]", ret);
    }

    workers = calloc(num_threads, sizeof(pthread_t));
    if (!workers) {
        pep_error("Failed to create threads pool of %d threads!", num_threads);
    }
    for (size_t i = 0; i < num_threads; ++i) {
        ret = pthread_create(&workers[i], NULL, workers_loop, wkr_args);
        if (ret != 0) {
            pep_error("Failed to create %d thread in pool! [RET = %d]", i + 1, ret);
        }
    }

    PEP_DEBUG("Pepsal started...");
    void* valptr;
    pthread_join(listener, &valptr);
    pthread_join(poller, &valptr);
    pthread_join(timer_sch, &valptr);
    for (size_t i = 0; i < num_threads; ++i) {
        pthread_join(workers[i], &valptr);
    }
}

void parse_arguments(int argc, char* argv[], int* thread_count, int* background, struct listener_thread_arguments* lst_args, struct scheduler_thread_arguments* sch_args)
{
    unsigned int max_conns = (PEP_MIN_CONNS + PEP_MAX_CONNS) / 2, monitoring_pid = 0;
    struct pep_sockopt sockopts;
    memset(&sockopts, 0, sizeof(struct pep_sockopt));
    sockopt_init();

    struct congestion_list cc_algorithms;
    congestion_control_init(&cc_algorithms);

    struct option long_options[] = {
        { "daemon", 1, 0, 'd' },
        { "verbose", 1, 0, 'v' },
        { "help", 0, 0, 'h' },
        { "fastopen", 0, 0, 'f' },
        { "port", 1, 0, 'p' },
        { "version", 0, 0, 'V' },
        { "logfile", 1, 0, 'l' },
        { "gc_interval", 1, 0, 'g' },
        { "plifetime", 1, 0, 't' },
        { "conns", 1, 0, 'c' },
        { "threads", 1, 0, 'T' },
        { "quickack", 0, 0, 'q' },
        { "nodelay", 0, 0, 'n' },
        { "corck", 0, 0, 'k' },
        { "congestion_algo", 0, 0, 'C' },
        { "max_segment_size", 0, 0, 'm' },
        { "monitoring_pid", 0, 0, 'M' },
        { 0, 0, 0, 0 }, // Sentinel
    };

    while (1) {
        int option_index = 0;
        int c = getopt_long(argc,
            argv,
            "dvVhfqnkp:a:l:g:t:c:T:C:m:M:",
            long_options,
            &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'd':
            *background = 1;
            break;
        case 'v':
            DEBUG = 1;
            break;
        case 'h':
            usage(argv[0]); // implies exit
            break;
        case 'f':
            sockopts.fastopen = 1;
            break;
        case 'p':
            lst_args->port_number = atoi(optarg);
            break;
        case 'l':
            sch_args->logger_filename = optarg;
            break;
        case 't':
            sch_args->pending_conn_lifetime = atoi(optarg);
            break;
        case 'g':
            sch_args->gc_interval = atoi(optarg);
            break;
        case 'c':
            max_conns = atoi(optarg);
            if ((max_conns < PEP_MIN_CONNS) || (max_conns > PEP_MAX_CONNS)) {
                usage(argv[0]);
            }
            break;
        case 'T':
            *thread_count = atoi(optarg);
            break;
        case 'q':
            sockopts.quickack = 1;
            break;
        case 'n':
            sockopts.nodelay = 1;
            break;
        case 'k':
            sockopts.corck = 1;
            break;
        case 'C':
            strncpy(sockopts.congestion_algo, optarg, CONGESTION_ALGORITHM_SIZE);
            if (congestion_control_exists(&cc_algorithms, sockopts.congestion_algo) != 0) {
                fprintf(stderr,
                    "Requested congestion control algorithm is not "
                    "available on the system \n");
                usage(argv[0]);
            }
            break;
        case 'm':
            sockopts.maxseg_size = atoi(optarg);
            break;
        case 'M':
            monitoring_pid = atoi(optarg);
            break;
        case 'V':
            printf("PEPSal ver. %s\n", VERSION);
            exit(EXIT_SUCCESS);
        }
    }

    congestion_control_destroy(&cc_algorithms);
    sockopt_edit(&sockopts);

    if (init_conn_tracker(max_conns, monitoring_pid) != 0) {
        pep_error("Failed to set new ressources limits");
    }
}

int main(int argc, char* argv[])
{
#ifndef DISABLE_SYSLOG
    openlog(PROGRAM_NAME, LOG_PID, LOG_DAEMON);
#endif
    /*
     * Main queues for connections and work synchronization
     * active_queue is used to transfer read/write jobs to
     * worker threads from PEP threads pool. After all jobs in
     * active_queue are done, they're moved to the ready_queue
     * which is used by poller thread. After poller thread wakes up,
     * it cheks out all connections from ready_queue, checks their status,
     * updates metainformation and restarts polling loop.
     */
    struct pep_queue active_queue, ready_queue;
    int peppool_threads = PEPPOOL_THREADS, background = 0;
    struct listener_thread_arguments lst_args = {
        .port_number = PEP_DEFAULT_PORT,
    };
    struct poller_thread_arguments poll_args = {
        .active_queue = &active_queue,
        .ready_queue = &ready_queue,
    };
    struct scheduler_thread_arguments sch_args = {
        .gc_interval = PEP_GC_INTERVAL,
        .pending_conn_lifetime = PEP_PENDING_CONN_LIFETIME,
        .logger_filename = NULL,
    };
    struct worker_thread_arguments wrk_args = {
        .active_queue = &active_queue,
        .ready_queue = &ready_queue,
    };
    parse_arguments(argc, argv, &peppool_threads, &background, &lst_args, &sch_args);

    if (background) {
        PEP_DEBUG("Daemonizing...");
        if (daemon(0, 1) < 0) {
            pep_error("daemon() failed!");
        }
    }

    PEP_DEBUG("Init SYN table with %d max connections", get_max_connections());
    if (syntab_init(get_max_connections()) < 0) {
        pep_error("Failed to initialize SYN table!");
    }

    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    lst_args.epoll_fd = epoll_fd;
    poll_args.epoll_fd = epoll_fd;
    wrk_args.epoll_fd = epoll_fd;
    sch_args.epoll_fd = epoll_fd;

    block_poller_signal();
    PEP_DEBUG("Initialize PEP queue for active connections...");
    pepqueue_init(&active_queue);
    PEP_DEBUG("Initialize PEP queue for handled connections...");
    pepqueue_init(&ready_queue);
    serve_forever(peppool_threads, &lst_args, &poll_args, &sch_args, &wrk_args);

    PEP_DEBUG("exiting...\n");
    sockopt_destroy();
    close(epoll_fd);
    closelog();

    return EXIT_SUCCESS;
}
