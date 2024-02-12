#ifndef __SOCK_OPT_H
#define __SOCK_OPT_H

#include "congestionlist.h"

struct pep_sockopt {
    int fastopen;
    int quickack;
    int nodelay;
    int cork;
    int maxseg_size;
    char congestion_algo[CONGESTION_ALGORITHM_SIZE];
};

void sockopt_init(void);
int sockopt_is_fastopen(void);
void sockopt_read(struct pep_sockopt* opts);
void sockopt_edit(struct pep_sockopt* opts);
void sockopt_destroy(void);

#endif // __SOCK_OPT_H
