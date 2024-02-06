#ifndef __CONGESTION_LIST_H
#define __CONGESTION_LIST_H

#include "list.h"
#include "pepdefs.h"

#define CONGESTION_ALGORITHM_SIZE 16

struct congestion_list {
    struct list_head queue;
    int num_items;
};

struct congestion_control {
    struct list_node node;
    char algorithm_name[CONGESTION_ALGORITHM_SIZE];
};

void congestion_control_init(struct congestion_list* cc);
int congestion_control_exists(struct congestion_list* cc, char* name);
void congestion_control_destroy(struct congestion_list* cc);

#endif
