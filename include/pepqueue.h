/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Dan Kruchinin <dkruchinin@acm.org> 2010
 * See AUTHORS and COPYING before using this software.
 *
 */

#ifndef __PEPQUEUE_H
#define __PEPQUEUE_H

#include "list.h"
#include "pepdefs.h"
#include <pthread.h>

struct pep_proxy;


/**
 * @struct pep_queue
 * @brief Linked-list accessor to manage connections proxies with
 *        builtin mutex support.
 */
struct pep_queue {
    struct list_head queue;
    int num_items;
    pthread_mutex_t mutex;
    pthread_cond_t condvar;
};


/**
 * @def PEPQUEUE_LOCK(pq)
 * @brief Blocks until single access is granted to the provided queue.
 * @param pq - the struct pep_queue that we need exclusive access from
 */
#define PEPQUEUE_LOCK(pq) pthread_mutex_lock(&(pq)->mutex)


/**
 * @def PEPQUEUE_UNLOCK(pq)
 * @brief Release the lock of the provided queue.
 * @param pq - the struct pep_queue that we release access from
 */
#define PEPQUEUE_UNLOCK(pq) pthread_mutex_unlock(&(pq)->mutex)


/**
 * @def PEPQUEUE_WAIT(pq)
 * @brief Wait for notifications on the provided queue.
 * @param pq - the struct pep_queue that we want to wait on
 */
#define PEPQUEUE_WAIT(pq) pthread_cond_wait(&(pq)->condvar, &(pq)->mutex)


/**
 * @def PEPQUEUE_WAKEUP_WAITERS(pq)
 * @brief Notify the provided queue and resume one thread waiting on it.
 * @param pq - the struct pep_queue that we want to notify
 */
#define PEPQUEUE_WAKEUP_WAITERS(pq) pthread_cond_signal(&(pq)->condvar)


/**
 * @brief Initialize the linked-list this queue is refering to
 * @param pq - the struct pep_queue to initialize
 * @return 0 on success, -1 otherwise
 */
int pepqueue_init(struct pep_queue* pq);


/**
 * @brief Append the specified connection proxy to the queue
 * @param pq - the struct pep_queue to append into
 * @param endp - the proxy to store in the queue
 */
void pepqueue_enqueue(struct pep_queue* pq, struct pep_proxy* endp);


/**
 * @brief Bulk append the specified connection proxies to the queue
 * @param pq - the struct pep_queue to append into
 * @param list - entry point to another link-list of proxies to store
 *               in the queue
 * @param num_items - amount of proxies in list to retrieve and append
 *                    in pq
 */
void pepqueue_enqueue_list(struct pep_queue* pq,
    struct list_head* list, int num_items);


/**
 * @brief Retrieve the first connection proxy stored in the queue and
 *        remove it from the linked-list.
 * @param pq - the struct pep_queue to retrieve the proxy from
 * @return the first connection proxy stored in pq, or NULL if the
 *         the queue is empty
 */
struct pep_proxy* pepqueue_dequeue(struct pep_queue* pq);


/**
 * @brief Dump the content of the provided queue into the provided
 *        linked-list and clear the queue.
 * @param pq - the struct pep_queue to retrieve the proxies from
 * @param list - the linked-list to dump proxies into
 */
void pepqueue_dequeue_list(struct pep_queue* pq, struct list_head* list);

#endif /* __PEPQUEUE_H */
