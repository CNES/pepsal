#include "sockoptions.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t sockopt_mutex;
static struct pep_sockopt socket_options;

void sockopt_init(void)
{
    memset(&socket_options, 0, sizeof(socket_options));

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&sockopt_mutex, &attr);
}

int sockopt_is_fastopen(void)
{
    int fastopen;
    pthread_mutex_lock(&sockopt_mutex);
    fastopen = socket_options.fastopen;
    pthread_mutex_unlock(&sockopt_mutex);
    return fastopen;
}

void sockopt_read(struct pep_sockopt* opts)
{
    pthread_mutex_lock(&sockopt_mutex);
    memcpy(opts, &socket_options, sizeof(socket_options));
    pthread_mutex_unlock(&sockopt_mutex);
}

void sockopt_edit(struct pep_sockopt* opts)
{
    pthread_mutex_lock(&sockopt_mutex);
    memcpy(&socket_options, opts, sizeof(socket_options));
    pthread_mutex_unlock(&sockopt_mutex);
}

void sockopt_destroy(void)
{
    pthread_mutex_destroy(&sockopt_mutex);
    memset(&socket_options, 0, sizeof(socket_options));
}
