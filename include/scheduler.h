#ifndef __SCHEDULER_H
#define __SCHEDULER_H

struct scheduler_thread_arguments {
    int gc_interval;
    int pending_conn_lifetime;
    int epoll_fd;
    char* logger_filename;
};

void* timer_sch_loop(void* arg);

#endif // __SCHEDULER_H
