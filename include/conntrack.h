/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyright Thales Alenia Space 2024
 * See AUTHORS and COPYING before using this software.
 *
 */


/**
 * @brief Monitor the amount of connections openned through PEPSal
 *        and, optionally, send information to an external process.
 */


#ifndef __CONN_TRACK_H
#define __CONN_TRACK_H


/**
 * @brief Initialize the connection tracker internal state
 * @param max_connections - The amount of connections we aim to not reach
 * @param pid - A pid to signal upon reaching max connections / having
 *              some room for new connections again. Will not send any
 *              signal if pid is 0.
 * @return 0 on succes, something else otherwise
 */
int init_conn_tracker(unsigned int max_connections, unsigned int pid);


/**
 * @brief Return the amount of max connection the tracker internal state
 *        was configured with
 * @return the max_connections value passed to init_conn_tracker
 */
unsigned int get_max_connections(void);


/**
 * @brief Increase the internal state of the tracker by 1 connection
 *        If the tracker reach 99% capacity, the SIGUSR1 signal will
 *        be sent to the pid the tracker was configured with.
 */
void increase_connection_count(void);


/**
 * @brief Increase the internal state of the tracker by 1 connection
 *        If the tracker drops down to 95% capacity, the SIGUSR2 signal
 *        will be sent to the pid the tracker was configured with.
 */
void decrease_connection_count(void);


#endif //__CONN_TRACK_H
