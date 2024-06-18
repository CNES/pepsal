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


#include "conntrack.h"
#include "listener.h"
#include "log.h"
#include "pepqueue.h"
#include "poller.h"
#include "scheduler.h"
#include "sniffer.h"
#include "sockoptions.h"
#include "syntab.h"
#include "workers.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <getopt.h>

static void
usage(const char* preamble, const char* progname, int success)
{
    FILE* output = success ? stdout : stderr;
    fprintf(output, "%s"
                    "\n\nusage: %s [-h] [-V] [-v] [-d] [-f] [-q] [-n] [-k] [-p PORT]"
                    "\n       [-c MAXCONN] [-l LOGFILE] [-t LIFETIME] [-g INTERVAL] [-T THREADS]"
                    "\n       [-C ALGORITHM] [-m MSS] [-M PID] [-s INTERFACE]"
                    "\n\nbehavioral options:"
                    "\n  -h, --help              print this help and exit"
                    "\n  -V, --version           print the program version and exit"
                    "\n  -v, --verbose           enable printing debug statements"
                    "\n  -d, --daemon            run in background"
                    "\n  -p PORT, --port PORT    bind listening socket to this PORT"
                    "\n  -c MAXCONN, --conns MAXCONN"
                    "\n                          allow up to MAXCONN connections to be handled"
                    "\n  -l LOGFILE, --logfile LOGFILE"
                    "\n                          enable periodic dumps of the syn table into LOGFILE"
                    "\n  -t LIFETIME, --plifetime LIFETIME"
                    "\n                          maximum lifetime of a stale connection before being"
                    "\n                          garbage collected"
                    "\n  -g INTERVAL, --gc-interval INTERVAL"
                    "\n                          run the connections garbage collector every INTERVAL"
                    "\n                          seconds"
                    "\n  -T THREADS, --threads THREADS"
                    "\n                          amount of worker threads to use"
                    "\n\nTCP options:"
                    "\n  -f, --fastopen          enable TCP fast open on listening and outgoing"
                    "\n                          sockets"
                    "\n  -q, --quickack          enable TCP quick ACK on outgoing sockets"
                    "\n  -n, --nodelay           enable TCP no delay on outgoing sockets"
                    "\n  -k, --cork              enable TCP CORK on outgoing sockets"
                    "\n  -C ALGORITHM, --congestion-algo ALGORITHM"
                    "\n                          name of the TCP congestion control algorithm to use"
                    "\n                          on outgoing sockets"
                    "\n  -m MSS, --max-segment-size MSS"
                    "\n                          enable the TCP maximum segment size option on"
                    "\n                          outgoing sockets and set it to MSS bytes"
                    "\n\nsystem integration options:"
                    "\n  -M PID, --monitoring-pid PID"
                    "\n                          enable alerts on process id PID when reaching close"
                    "\n                          to MAXCONN opened connections (SIGUSR1 will be sent"
                    "\n                          when reaching 99%% of opened connections and SIGUSR2"
                    "\n                          when capacity drops back to 95%%)"
                    "\n  -s INTERFACE, --sniff-interface INTERFACE"
                    "\n                          name of an INTERFACE to sniff and extract ethernet"
                    "\n                          or IP options from SYN packets in order to replicate"
                    "\n                          them on outgoing sockets"
                    "\n",
        preamble, progname);
    SYSLOG_BEHAVIOUR(closelog(););
    if (success) {
        exit(EXIT_SUCCESS);
    } else {
        exit(EXIT_FAILURE);
    }
}

static inline void
serve_forever(int num_threads,
    struct listener_thread_arguments* lst_args,
    struct poller_thread_arguments* poll_args,
    struct scheduler_thread_arguments* sch_args,
    struct worker_thread_arguments* wkr_args,
    struct sniffer_thread_arguments* snf_args)
{
    int ret;
    pthread_t listener, poller, timer_sch, sniffer, *workers;

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

    PEP_DEBUG("Creating sniffer thread");
    ret = pthread_create(&sniffer, NULL, sniffer_loop, snf_args);
    if (ret != 0) {
        pep_error("Failed to create the sniffer thread! [RET = %d]", ret);
    }

    workers = calloc(num_threads, sizeof(*workers));
    if (!workers) {
        pep_error("Failed to create threads pool of %d threads!", num_threads);
    }
    for (size_t i = 0; i < num_threads; ++i) {
        ret = pthread_create(&workers[i], NULL, workers_loop, wkr_args);
        if (ret != 0) {
            pep_error("Failed to create %zu thread in pool! [RET = %d]", i + 1, ret);
        }
    }

    PEP_DEBUG("Pepsal started...");
    void* valptr;
    pthread_join(listener, &valptr);
    pthread_join(poller, &valptr);
    pthread_join(timer_sch, &valptr);
    pthread_join(sniffer, &valptr);
    for (size_t i = 0; i < num_threads; ++i) {
        pthread_join(workers[i], &valptr);
    }
}

void parse_arguments(int argc, char* argv[], int* thread_count, int* background,
    struct listener_thread_arguments* lst_args,
    struct scheduler_thread_arguments* sch_args,
    struct sniffer_thread_arguments* snf_args)
{
    unsigned int max_conns = (PEP_MIN_CONNS + PEP_MAX_CONNS) / 2, monitoring_pid = 0;
    struct pep_sockopt sockopts;
    memset(&sockopts, 0, sizeof(sockopts));
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
        { "cork", 0, 0, 'k' },
        { "congestion-algo", 0, 0, 'C' },
        { "max-segment-size", 0, 0, 'm' },
        { "monitoring-pid", 0, 0, 'M' },
        { "sniff-interface", 0, 0, 's' },
        { 0, 0, 0, 0 }, // Sentinel
    };

    while (1) {
        int option_index = 0;
        int c = getopt_long(argc,
            argv,
            "dvVhfqnkp:l:g:t:c:T:C:m:M:s:",
            long_options,
            &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h': {
            char preamble[1100];
            snprintf(preamble, sizeof(preamble),
                "%s - A Performance Enhancing Proxy for TCP satellite connections"
                "\n\n    %s is a Performance Enhancing Proxy, used for optimizing TCP connections"
                "\non satellite links. It works at multiple layers (IP, TCP, and Application): it"
                "\nuses netfilter to intercept those connections that would involve a satellite"
                "\nlinks and \"steals\" the TCP SYN packet in the three-way handshake phase of a TCP"
                "\nconnection, then pretends to be the other side of that connection, and initiate"
                "\na new connection to the real endpoint, using a userspace application that"
                "\ndirectly copy data between the two sockets. It thus effectively splits the TCP"
                "\nconnection in two."
                "\n\n    %s represents a valid solution for the degraded TCP performance when"
                "\nsatellite links are involved. It does not require modifications on content"
                "\nservers, or satellite receivers, it is sufficient to set it up in a computer"
                "\ntraversed by the TCP connections. It is designed to follow the advices in IETF"
                "\nRFC3135, to implement a simple TCP split technique.",
                PACKAGE_STRING, PACKAGE_NAME, PACKAGE_NAME);
            usage(preamble, argv[0], 1);
            break;
        }
        case 'd':
            *background = 1;
            break;
        case 'v':
            DEBUG = 1;
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
                char preamble[100];
                snprintf(preamble, sizeof(preamble),
                    "maximum number of connections should be between %d and %d, not %d",
                    PEP_MIN_CONNS, PEP_MAX_CONNS, max_conns);
                usage(preamble, argv[0], 0);
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
            sockopts.cork = 1;
            break;
        case 'C':
            strncpy(sockopts.congestion_algo, optarg, CONGESTION_ALGORITHM_SIZE - 1);
            if (congestion_control_exists(&cc_algorithms, sockopts.congestion_algo) != 0) {
                char preamble[100];
                snprintf(preamble, sizeof(preamble),
                    "congestion control algorithm '%s' is not available on the system",
                    sockopts.congestion_algo);
                usage(preamble, argv[0], 0);
            }
            break;
        case 'm':
            sockopts.maxseg_size = atoi(optarg);
            break;
        case 'M':
            monitoring_pid = atoi(optarg);
            break;
        case 's':
            snf_args->interface_name = optarg;
            break;
        case 'V':
            printf("%s ver. %s\n", PACKAGE_NAME, VERSION);
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
    SYSLOG_BEHAVIOUR(openlog(PROGRAM_NAME, LOG_PID | LOG_NDELAY, LOG_DAEMON););
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
    struct sniffer_thread_arguments snf_args = {
        .interface_name = NULL,
    };
    parse_arguments(argc, argv, &peppool_threads, &background, &lst_args, &sch_args, &snf_args);

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
    snf_args.epoll_fd = epoll_fd;

    block_poller_signal();
    PEP_DEBUG("Initialize PEP queue for active connections...");
    pepqueue_init(&active_queue);
    PEP_DEBUG("Initialize PEP queue for handled connections...");
    pepqueue_init(&ready_queue);
    serve_forever(peppool_threads, &lst_args, &poll_args, &sch_args, &wrk_args, &snf_args);

    PEP_DEBUG("exiting...\n");
    sockopt_destroy();
    close(epoll_fd);
    SYSLOG_BEHAVIOUR(closelog(););

    return EXIT_SUCCESS;
}
