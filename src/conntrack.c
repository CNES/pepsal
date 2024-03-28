/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyright Thales Alenia Space 2024
 * See AUTHORS and COPYING before using this software.
 *
 */


#include "conntrack.h"
#include <math.h>
#include <signal.h>
#include <sys/resource.h>

enum connection_state {
    ACCEPTING_CONNECTIONS,
    REFUSING_CONNECTIONS,
};

enum connection_state state;
static unsigned int connections = 0;
static unsigned int max_conns = 0;
static unsigned int stop_limit = 0, allow_limit = 0;
static unsigned int monitoring_pid = 0;

int init_conn_tracker(unsigned int max_connections, unsigned int pid)
{
    state = ACCEPTING_CONNECTIONS;
    connections = 0;
    monitoring_pid = pid;
    max_conns = max_connections;

    allow_limit = round(0.95 * max_connections);
    stop_limit = round(0.99 * max_connections);

    /*setting new ressources limit*/
    struct rlimit new_lim;
    new_lim.rlim_cur = (10 * max_conns);
    new_lim.rlim_max = 1048576;
    return setrlimit(RLIMIT_NOFILE, &new_lim);
}

unsigned int get_max_connections(void)
{
    return max_conns;
}

void increase_connection_count()
{
    if ((++connections) == stop_limit && state == ACCEPTING_CONNECTIONS) {
        state = REFUSING_CONNECTIONS;
        if (monitoring_pid != 0) {
            kill(monitoring_pid, SIGUSR1);
        }
    }
}

void decrease_connection_count()
{
    if ((--connections) == allow_limit && state == REFUSING_CONNECTIONS) {
        state = ACCEPTING_CONNECTIONS;
        if (monitoring_pid != 0) {
            kill(monitoring_pid, SIGUSR2);
        }
    }
}
