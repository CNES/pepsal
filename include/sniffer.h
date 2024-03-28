/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyright Thales Alenia Space 2024
 * See AUTHORS and COPYING before using this software.
 *
 */


/**
 * @brief Utilities to run a sniffer thread.
 *        Sniffer thread is responsible of monitoring a network
 *        interface and creating a new connection proxy for each
 *        TCP SYN packet received. Its main purpose is to replicate
 *        some of the IP options from the initial connection to the
 *        proxied one.
 */


#ifndef __SNIFFER_H
#define __SNIFFER_H


/**
 * @struct sniffer_thread_arguments
 * @brief Encapsulate arguments that are necessary to run the
 *        scheduler thread
 */
struct sniffer_thread_arguments {
    int epoll_fd;
    char* interface_name;
};


/**
 * @brief Core scheduler thread function. Intended to be started by
 *        pthread with a struct sniffer_thread_arguments* as
 *        parameter.
 * @param arg - a sniffer_thread_arguments struct to configure the
 *              loop from
 * @return NULL as the thread is not meant to finish on its own,
 *         this is only to conform to the pthread arguments signature.
 */
void* sniffer_loop(void* arg);

#endif // __SNIFFER_H
