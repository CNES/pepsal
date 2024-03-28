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
 * @brief Utilities to run a scheduler thread.
 *        Scheduler thread routinely performs connections housekeeping
 *        and data dumps.
 */


#ifndef __SCHEDULER_H
#define __SCHEDULER_H


/**
 * @struct scheduler_thread_arguments
 * @brief Encapsulate arguments that are necessary to run the
 *        scheduler thread
 */
struct scheduler_thread_arguments {
    int gc_interval;
    int pending_conn_lifetime;
    int epoll_fd;
    char* logger_filename;
};


/**
 * @brief Core scheduler thread function. Intended to be started by
 *        pthread with a struct scheduler_thread_arguments* as
 *        parameter.
 * @param arg - a scheduler_thread_arguments struct to configure the
 *              loop from
 * @return NULL as the thread is not meant to finish on its own,
 *         this is only to conform to the pthread arguments signature.
 */
void* timer_sch_loop(void* arg);

#endif // __SCHEDULER_H
