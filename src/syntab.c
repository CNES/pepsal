/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Dan Kruchinin <dkruchinin@acm.org> 2010
 * Copyright CNES 2017
 * See AUTHORS and COPYING before using this software.
 *
 */


#include "syntab.h"
#include "config.h"
#include "log.h"
#include "pepsal.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct syn_table syntab;

/* Define type safe functions instead of those using/returning void* */
static inline DEFINE_HASHTABLE_INSERT(__syntab_insert, struct syntab_key, struct pep_proxy);
static inline DEFINE_HASHTABLE_SEARCH(__syntab_find, struct syntab_key, struct pep_proxy);
static inline DEFINE_HASHTABLE_REMOVE(__syntab_remove, struct syntab_key, struct pep_proxy);

/* Bob Jenkin's MIX64 function */
#define BJ_MIX(a, b, c) \
    do {                \
        a -= b;         \
        a -= c;         \
        a ^= (c >> 13); \
        b -= c;         \
        b -= a;         \
        b ^= (a << 8);  \
        c -= a;         \
        c -= b;         \
        c ^= (b >> 13); \
        a -= b;         \
        a -= c;         \
        a ^= (c >> 12); \
        b -= c;         \
        b -= a;         \
        b ^= (a << 16); \
        c -= a;         \
        c -= b;         \
        c ^= (b >> 5);  \
        a -= b;         \
        a -= c;         \
        a ^= (c >> 3);  \
        b -= c;         \
        b -= a;         \
        b ^= (a << 10); \
        c -= a;         \
        c -= b;         \
        c ^= (b >> 15); \
    } while (0)

static unsigned int
syntab_hashfunction(void* k)
{
    struct syntab_key* sk = k;
    unsigned int a, b, c;
    uint8_t key[16];

    memcpy(key, sk->addr8, 16 * sizeof(*key));
    c = sk->port;
    a = b = 0x9e3779b9; /* the golden ratio */

    /* Robert Jenkins' 32 bit integer hash function */
    a = a + (key[0] + (key[1] << 8) + (key[2] << 16) + (key[3] << 24));
    b = b + (key[4] + (key[5] << 8) + (key[6] << 16) + (key[7] << 24));
    c = c + (key[8] + (key[9] << 8) + (key[10] << 16) + (key[11] << 24));
    BJ_MIX(a, b, c);

    c += 16;
    a = a + (key[15] << 24);
    a = a + (key[14] << 16);
    a = a + (key[13] << 8);
    a = a + key[12];
    BJ_MIX(a, b, c);

    return c;
}

static int
__keyeqfn(void* k1, void* k2)
{
    return (memcmp(k1, k2, sizeof(struct syntab_key)) == 0);
}

int syntab_init(int num_conns)
{
    int ret, hash_size;

    memset(&syntab, 0, sizeof(syntab));
    hash_size = (num_conns * 125) / 100; /* ~125% of max number of connections */
    syntab.hash = create_hashtable(hash_size, syntab_hashfunction, __keyeqfn);
    if (!syntab.hash) {
        errno = ENOMEM;
        return -1;
    }

    pthread_rwlockattr_t attr;
    ret = pthread_rwlockattr_init(&attr);
    if (ret) {
        ret = errno;
        hashtable_destroy(syntab.hash, 0);
        errno = ret;
        return -1;
    }

    ret = pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)
        || pthread_rwlock_init(&syntab.lock, &attr);
    if (ret) {
        ret = errno;
        hashtable_destroy(syntab.hash, 0);
        pthread_rwlockattr_destroy(&attr);
        errno = ret;
        return -1;
    }

    pthread_rwlockattr_destroy(&attr);
    list_init_head(&syntab.conns);
    syntab.num_items = 0;

    return 0;
}

static __inline void
__syntab_format_key(struct pep_proxy* proxy, struct syntab_key* key)
{
    memcpy(key->addr, proxy->src.addr, 8 * sizeof(*key->addr));
    key->port = proxy->src.port;
#ifdef ENABLE_DST_IN_KEY
    memcpy(key->dst_addr, proxy->dst.addr, 8 * sizeof(*key->dst_addr));
    key->dst_port = proxy->dst.port;
#endif
}

void syntab_format_key(struct pep_proxy* proxy, struct syntab_key* key)
{
    __syntab_format_key(proxy, key);
}

struct pep_proxy*
syntab_find(struct syntab_key* key)
{
    return __syntab_find(syntab.hash, key);
}

int syntab_add(struct pep_proxy* proxy)
{
    struct syntab_key* key;
    int ret;

    assert(proxy->status == PST_PENDING);
    key = calloc(1, sizeof(*key));
    if (!key) {
        errno = ENOMEM;
        return -1;
    }

    __syntab_format_key(proxy, key);
    ret = __syntab_insert(syntab.hash, key, proxy);
    if (ret == 0) {
        free(key);
        return -1;
    }

    list_add2tail(&syntab.conns, &proxy->lnode);
    syntab.num_items++;

    return 0;
}

void syntab_delete(struct pep_proxy* proxy)
{
    struct syntab_key key;

    __syntab_format_key(proxy, &key);
    __syntab_remove(syntab.hash, &key);
    list_del(&proxy->lnode);
    syntab.num_items--;
}

int syntab_add_if_not_duplicate(struct pep_proxy* proxy)
{
    struct syntab_key key;

    __syntab_format_key(proxy, &key);
    SYNTAB_LOCK_WRITE();
    struct pep_proxy* dup = __syntab_find(syntab.hash, &key);
    if (dup != NULL) {
        PEP_DEBUG_DP(dup, "Duplicate SYN. Dropping...");
        SYNTAB_UNLOCK_WRITE();
        return -1;
    }

    /* add to the table... */
    proxy->status = PST_PENDING;
    int ret = syntab_add(proxy);
    SYNTAB_UNLOCK_WRITE();
    return ret;
}
