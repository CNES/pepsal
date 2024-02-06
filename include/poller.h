#ifndef __POLLER_H
#define __POLLER_H

#include <pthread.h>

struct pep_queue;

struct poller_thread_arguments {
    int epoll_fd;
    struct pep_queue* active_queue;
    struct pep_queue* ready_queue;
};

void block_poller_signal(void);
void* poller_loop(void* arg);
void signal_new_connection_to_poller(pthread_t poller);

#endif // __POLLER_H
