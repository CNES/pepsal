#ifndef __SNIFFER_H
#define __SNIFFER_H

struct sniffer_thread_arguments {
    int epoll_fd;
    char* interface_name;
};

void* sniffer_loop(void* arg);

#endif // __SNIFFER_H
