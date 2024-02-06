#ifndef __LISTENER_H
#define __LISTENER_H

#include <pthread.h>

struct listener_thread_arguments {
    int port_number;
    int epoll_fd;
    pthread_t poller;
};

void* listener_loop(void* arg);

#endif //__LISTENER_H
