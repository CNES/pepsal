/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005-2007
 * Copyleft Dan Kruchinin <dkruchinin@acm.org> 2010
 * Copyright CNES 2017
 * See AUTHORS and COPYING before using this software.
 *
 */


/**
 * @brief Utilities to manage the hashtable used for connections (SYN)
 *        tracking.
 */


#ifndef __PEPSAL_SYNTAB_H
#define __PEPSAL_SYNTAB_H
#include "config.h"
#include "hashtable.h"
#include "list.h"
#include "pepsal.h"
#include <pthread.h>


/**
 * @struct syn_table
 * @brief Encapsulate mutually exclusive access to the SYN hashtable.
 */
struct syn_table {
    struct hashtable* hash;
    struct list_head conns;
    pthread_rwlock_t lock;
    int num_items;
};


/**
 * @struct syntab_key
 * @brief Structure serving as a key in the hashtable to retrieve an
 *        associated proxied connection.
 */
struct syntab_key {
    union {
        uint16_t addr[8];
        uint8_t addr8[16];
    };
#ifdef ENABLE_DST_IN_KEY
    union {
        uint16_t dst_addr[8];
        uint8_t dst_addr8[16];
    };
#endif
    unsigned short port;
#ifdef ENABLE_DST_IN_KEY
    unsigned short dst_port;
#endif
} __attribute__((packed));


/**
 * @def GET_SYNTAB
 * @brief Access the global SYN hashtable.
 */
#define GET_SYNTAB() (&syntab)


/**
 * @def SYNTAB_LOCK_READ
 * @brief Lock the global SYN hashtable for read accesses.
 */
#define SYNTAB_LOCK_READ() do { PEP_DEBUG("SYNTAB_LOCK_READ"); pthread_rwlock_rdlock(&(GET_SYNTAB())->lock); } while(0)


/**
 * @def SYNTAB_LOCK_WRITE
 * @brief Lock the global SYN hashtable for write accesses.
 */
#define SYNTAB_LOCK_WRITE() do { PEP_DEBUG("SYNTAB_LOCK_WRITE"); pthread_rwlock_wrlock(&(GET_SYNTAB())->lock); } while(0)


/**
 * @def SYNTAB_UNLOCK_READ
 * @brief Release the read lock on the global SYN hashtable.
 */
#define SYNTAB_UNLOCK_READ() do { PEP_DEBUG("SYNTAB_UNLOCK_READ"); pthread_rwlock_unlock(&(GET_SYNTAB())->lock); } while(0)


/**
 * @def SYNTAB_UNLOCK_WRITE
 * @brief Release the write lock on the global SYN hashtable.
 */
#define SYNTAB_UNLOCK_WRITE() do { PEP_DEBUG("SYNTAB_UNLOCK_WRITE"); pthread_rwlock_unlock(&(GET_SYNTAB())->lock); } while(0)

extern struct syn_table syntab;


/**
 * @def syntab_foreach_connection
 * @brief Simplify writing loops over all the connections stored in the
 *        global SYN hashtable.
 */
#define syntab_foreach_connection(con) \
    list_for_each_entry(&GET_SYNTAB()->conns, con, struct pep_proxy, lnode)


/**
 * @brief Initialise the SYN hashtable
 * @param num_conns - The maximum number of connections the table can handle
 */
int syntab_init(int num_conns);


/**
 * @brief Create a suitable hashtable key from the given connection proxy
 * @param proxy - the proxy to create a key for
 * @param key - [Output] the key to fill in with the proper informations
 */
void syntab_format_key(struct pep_proxy* proxy, struct syntab_key* key);


/**
 * @brief Extract a connection proxy from the hashtable that correspond
 *        to the given key.
 * @param key - the key of the proxy to look for
 * @return the proxy associated to the key in the hashtable, or NULL if
 *         no such proxy is found
 */
struct pep_proxy* syntab_find(struct syntab_key* key);


/**
 * @brief Add the given connection proxy into the SYN hashtable.
 * @param proxy - the proxy to add
 * @return 0 on success, something else otherwise
 */
int syntab_add(struct pep_proxy* proxy);


/**
 * @brief Remove the given connection proxy from the SYN hashtable.
 * @param proxy - the proxy to remove
 */
void syntab_delete(struct pep_proxy* proxy);


/**
 * @brief Add the given connection proxy into the SYN hashtable. Make
 *        sure that no other proxy with the same key is present before
 *        insertion.
 * @param proxy - the proxy to add
 * @return 0 on succes, something else otherwise
 */
int syntab_add_if_not_duplicate(struct pep_proxy* proxy);

#endif /* __PEPSAL_SYNTAB_H */
