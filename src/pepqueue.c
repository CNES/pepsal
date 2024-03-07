/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Dan Kruchinin <dkruchinin@acm.org> 2010
 * See AUTHORS and COPYING before using this software.
 *
 *
 *
 */

#include <assert.h>
#include <pthread.h>

#include "pepqueue.h"
#include "pepsal.h"

int pepqueue_init(struct pep_queue* pq)
{
    list_init_head(&pq->queue);

    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) {
        return -1;
    }
    if (pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) != 0
        || pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0
        || pthread_mutex_init(&pq->mutex, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }
    pthread_mutexattr_destroy(&attr);
    if (pthread_cond_init(&pq->condvar, NULL) != 0) {
        return -1;
    }

    pq->num_items = 0;
    return 0;
}

void pepqueue_enqueue(struct pep_queue* pq, struct pep_proxy* proxy)
{
    list_add2tail(&pq->queue, &proxy->qnode);
    pq->num_items++;
}

void pepqueue_enqueue_list(struct pep_queue* pq,
    struct list_head* list,
    int num_items)
{
    list_move2tail(&pq->queue, list);
    pq->num_items += num_items;
}

struct pep_proxy*
pepqueue_dequeue(struct pep_queue* pq)
{
    struct pep_proxy* proxy = NULL;

    if (pq->num_items == 0) {
        return NULL;
    }

    proxy = list_entry(list_node_first(&pq->queue), struct pep_proxy, qnode);
    list_del(&proxy->qnode);
    pq->num_items--;

    return proxy;
}

void pepqueue_dequeue_list(struct pep_queue* pq, struct list_head* lh)
{
    list_move2head(lh, &pq->queue);
    pq->num_items = 0;
}
