/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyright Thales Alenia Space 2024
 * See AUTHORS and COPYING before using this software.
 *
 */


/**
 * @brief Create and maintain a linked-list of TCP congestion
 *        control algorithms available on the machine running
 *        PEPSal.
 */


#ifndef __CONGESTION_LIST_H
#define __CONGESTION_LIST_H

#include "list.h"
#include "pepdefs.h"


/**
 * @brief Maximum length of a congestion control algorithm name
 *        including null-termination byte
 */
#define CONGESTION_ALGORITHM_SIZE 16


/**
 * @struct congestion_list
 * @brief Linked-list structure to hold congestion control algorithm names
 */
struct congestion_list {
    struct list_head queue;
    int num_items;
};


/**
 * @struct congestion_control
 * @brief Linked-list node to hold the name of a congestion control algorithm
 */
struct congestion_control {
    struct list_node node;
    char algorithm_name[CONGESTION_ALGORITHM_SIZE];
};


/**
 * @brief Initialize the congestion_list linked-list
 * @param cc - the congestion_list to initialize
 */
void congestion_control_init(struct congestion_list* cc);


/**
 * @brief Check wether a congestion control algorithm exists in the linked list
 * @param cc - the congestion_list to search into
 * @param name - the name of the congestion control algorithm to check for
 * @return 0 if name is found in cc, something else otherwise
 */
int congestion_control_exists(struct congestion_list* cc, char* name);


/**
 * @brief Reclaim memory from, and clear the congestion_list linked-list
 * @param cc - the congestion_list to destroy
 */
void congestion_control_destroy(struct congestion_list* cc);


#endif
