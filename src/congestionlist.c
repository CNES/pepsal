#include "congestionlist.h"
#include "log.h"
#include "pepsal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define READ_BUFFER_SIZE 1024

void congestion_control_init(struct congestion_list* cc)
{
    list_init_head(&cc->queue);
    cc->num_items = 0;

    FILE* file = fopen("/proc/sys/net/ipv4/tcp_available_congestion_control", "r");
    if (file == NULL) {
        pep_error("Failed to open /proc/sys/net/ipv4/tcp_available_congestion_control");
    }

    char buffer[READ_BUFFER_SIZE];
    if (fgets(buffer, READ_BUFFER_SIZE, file) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;
    } else {
        fclose(file);
        pep_error("Failed to retrieve congestion control algorithm names from the system");
    }

    fclose(file);

    const char* separators = " ";
    char* algo = strtok(buffer, separators);
    while (algo != NULL) {
        struct congestion_control* cc_algorithm;
        cc_algorithm = (struct congestion_control*)malloc(sizeof(struct congestion_control));
        if (cc_algorithm == NULL) {
            congestion_control_destroy(cc);
            pep_error("Failed to allocate memory for congestion control algorithm names storage");
        }
        strncpy(cc_algorithm->algorithm_name, algo, CONGESTION_ALGORITHM_SIZE);
        list_add2tail(&cc->queue, &cc_algorithm->node);
        cc->num_items++;
        algo = strtok(NULL, separators);
    }
}

int congestion_control_exists(struct congestion_list* cc, char* name)
{
    struct congestion_control* iter;
    list_for_each_entry(&cc->queue, iter, struct congestion_control, node)
    {
        if (strcmp(iter->algorithm_name, name) == 0) {
            return 0;
        }
    }

    return -1;
}

void congestion_control_destroy(struct congestion_list* cc)
{
    struct list_node *iter, *save;
    list_for_each_safe(&cc->queue, iter, save)
    {
        struct congestion_control* element = list_entry(iter, struct congestion_control, node);
        list_del(iter);
        free(element);
    }

    cc->num_items = 0;
}
