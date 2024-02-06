#ifndef __CONN_TRACK_H
#define __CONN_TRACK_H

int init_conn_tracker(unsigned int max_connections, unsigned int pid);
unsigned int get_max_connections(void);
void increase_connection_count(void);
void decrease_connection_count(void);

#endif //__CONN_TRACK_H
