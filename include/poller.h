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
 * @brief Utilities to run a poller thread.
 *        Poller thread waits on opened connections for I/O events and
 *        dispatch active connections to worker threads to be handled
 *        accordingly.
 *        Poller thread also monitor a signal to break out of system
 *        calls when a new connection has been added to the hashtable
 *        and requires monitoring.
 */


#ifndef __POLLER_H
#define __POLLER_H

#include <pthread.h>

struct pep_queue;


/**
 * @struct poller_thread_arguments
 * @brief Encapsulate arguments that are necessary to run the
 *        poller thread
 */
struct poller_thread_arguments {
    int epoll_fd;
    struct pep_queue* active_queue;
    struct pep_queue* ready_queue;
};


/**
 * @brief Core poller thread function. Intended to be started by
 *        pthread with a struct poller_thread_arguments* as parameter.
 * @param arg - a poller_thread_arguments struct to configure the
 *              loop from
 * @return NULL as the thread is not meant to finish on its own,
 *         this is only to conform to the pthread arguments signature.
 */
void* poller_loop(void* arg);


/**
 * @brief Disable the action associated to the signal used by the
 *        poller thread to monitor incomming connections.
 */
void block_poller_signal(void);


/**
 * @brief Send a specific signal to the poller thread to indicate that
 *        a new connection has been received and added to the hashtable.
 * @param poller - the thread handle of the poller thread
 */
void signal_new_connection_to_poller(pthread_t poller);

#endif // __POLLER_H
