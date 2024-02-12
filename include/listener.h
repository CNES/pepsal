#ifndef __LISTENER_H
#define __LISTENER_H

#include <pthread.h>

struct pep_proxy;

struct listener_thread_arguments {
    int port_number;
    int epoll_fd;
    pthread_t poller;
};

void* listener_loop(void* arg);
int configure_out_socket(struct pep_proxy* proxy, int is_ipv4);

#endif //__LISTENER_H
