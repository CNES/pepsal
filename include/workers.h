#ifndef __WORKERS_H
#define __WORKERS_H

struct pep_queue;

struct worker_thread_arguments {
    int epoll_fd;
    struct pep_queue* active_queue;
    struct pep_queue* ready_queue;
};

void* workers_loop(void* arg);

#endif // __WORKERS_H
