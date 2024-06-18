/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005-2007
 * Copyleft Dan Kruchinin <dkruchinin@acm.org> 2010
 * Copyright CNES 2017
 * Copyright Thales Alenia Space 2024
 * See AUTHORS and COPYING before using this software.
 *
 */


/**
 * @brief Utilities to run a worker thread.
 *        Worker threads are responsible of transferring data from one
 *        socket to the other in a proxied connection. They coordinate
 *        their actions with the poller thread through the use of
 *        queues.
 */


#ifndef __WORKERS_H
#define __WORKERS_H

struct pep_queue;


/**
 * @struct worker_thread_arguments
 * @brief Encapsulate arguments that are necessary to run the
 *        scheduler thread
 */
struct worker_thread_arguments {
    int epoll_fd;
    struct pep_queue* active_queue;
    struct pep_queue* ready_queue;
};


/**
 * @brief Core worker thread function. Intended to be started by
 *        pthread with a struct worker_thread_arguments* as
 *        parameter.
 * @param arg - a worker_thread_arguments struct to configure the
 *              loop from
 * @return NULL as the thread is not meant to finish on its own,
 *         this is only to conform to the pthread arguments signature.
 */
void* workers_loop(void* arg);

#endif // __WORKERS_H
