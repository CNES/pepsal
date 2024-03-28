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
 * @brief Utilities to run a listener thread.
 *        Listener thread accepts new connections comming into PEPSal
 *        and configure an output socket for each of these connections.
 */


#ifndef __LISTENER_H
#define __LISTENER_H

#include <pthread.h>

struct pep_proxy;


/**
 * @struct listener_thread_arguments
 * @brief Encapsulate arguments that are necessary to run the
 *        listener thread
 */
struct listener_thread_arguments {
    int port_number;
    int epoll_fd;
    pthread_t poller;
};


/**
 * @brief Core listener thread function. Intended to be started
 *        by pthread with a struct listener_thread_arguments* as
 *        parameter.
 * @param arg - a listener_thread_arguments struct to configure
 *              the loop from
 * @return NULL as the thread is not meant to finish on its own,
 *         this is only to conform to the pthread arguments signature.
 */
void* listener_loop(void* arg);


/**
 * @brief Helper function to create new output sockets and store them
 *        into the hashtable.
 * @param proxy - the hashtable entry where the new socket should be
 *                stored
 * @param is_ipv4 - whether to create an AF_INET or AF_INET6 socket
 * @return 0 on success, something else otherwise
 */
int configure_out_socket(struct pep_proxy* proxy, int is_ipv4);

#endif //__LISTENER_H
