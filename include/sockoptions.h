/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyright Thales Alenia Space 2024
 * See AUTHORS and COPYING before using this software.
 *
 */


/**
 * @brief Utilities to manage TCP options to apply on proxied
 *        connections.
 */


#ifndef __SOCK_OPT_H
#define __SOCK_OPT_H

#include "congestionlist.h"


/**
 * @struct pep_sockopt
 * @brief Values for interesting TCP options to apply on newly
 *        created sockets.
 */
struct pep_sockopt {
    int fastopen;
    int quickack;
    int nodelay;
    int cork;
    int maxseg_size;
    char congestion_algo[CONGESTION_ALGORITHM_SIZE];
};


/**
 * @brief Initialize the internal state of the socket options manager.
 */
void sockopt_init(void);


/**
 * @brief Retrieve the status of the fastopen option without having to
 *        read the whole pep_sockopt structure.
 * @return 1 if fastopen is set, 0 otherwise
 */
int sockopt_is_fastopen(void);


/**
 * @brief Retrieve the internal state of options into the provided
 *        pep_sockopt structure.
 * @param opts - [Output] structure to be filled in with stored options
 */
void sockopt_read(struct pep_sockopt* opts);


/**
 * @brief Edit the internal state of options with the values of the
 *        provided pep_sockopt structure.
 * @param opts - structure to be copied into the stored options
 */
void sockopt_edit(struct pep_sockopt* opts);


/**
 * @brief Clear the internal state of the socket options manager.
 */
void sockopt_destroy(void);

#endif // __SOCK_OPT_H
