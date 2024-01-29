/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Dan Kruchinin <dkruchinin@acm.org> 2010
 * Copyright CNES 2017
 * See AUTHORS and COPYING before using this software.
 *
 *
 *
 */
#include "config.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include "pepsal.h"
#include "syntab.h"

struct syn_table syntab;

/* Bob Jenkin's MIX64 function */
#define BJ_MIX(a, b, c)                            \
    do {                                           \
        a -= b; a -= c; a ^= (c>>13);              \
        b -= c; b -= a; b ^= (a<<8);               \
        c -= a; c -= b; c ^= (b>>13);              \
        a -= b; a -= c; a ^= (c>>12);              \
        b -= c; b -= a; b ^= (a<<16);              \
        c -= a; c -= b; c ^= (b>>5);               \
        a -= b; a -= c; a ^= (c>>3);               \
        b -= c; b -= a; b ^= (a<<10);              \
        c -= a; c -= b; c ^= (b>>15);              \
    } while (0)



static unsigned int syntab_hashfunction(void *k)
{
    struct syntab_key *sk = k;
    unsigned int a, b, c;
    uint8_t key[16];

    for (int i = 0; i < 16; ++i) {
        key[i] = sk->addr8[i];
    }
    c = sk->port;
    a = b = 0x9e3779b9; /* the golden ratio */

   /* Robert Jenkins' 32 bit integer hash function */
    a=a+(key[0]+(key[1]<<8)+(key[2]<<16) +(key[3]<<24));
    b=b+(key[4]+(key[5]<<8)+(key[6]<<16) +(key[7]<<24));
    c=c+(key[8]+(key[9]<<8)+(key[10]<<16)+(key[11]<<24));
    BJ_MIX(a, b, c);
    c += 16;
    a=a+(key[15]<<24);
    a=a+(key[14]<<16);
    a=a+(key[13]<<8);
    a=a+key[12];
    BJ_MIX(a, b, c);

    return c;
}

static int __keyeqfn(void *k1, void *k2)
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

    ret = pthread_rwlock_init(&syntab.lock, NULL);
    if (ret) {
        ret = errno;
        hashtable_destroy(syntab.hash, 0);
        errno = ret;
        return -1;
    }

    list_init_head(&syntab.conns);
    syntab.num_items = 0;

    return 0;
}

static __inline void syntab_make_key(struct syntab_key *key,
                                     uint16_t addr[8], unsigned short port,
                                     unsigned short dst_port, uint16_t dst_addr[8])
{
    memset(key, 0, sizeof(*key));
    for(size_t i; i<8;i++){
        (key->addr)[i] = addr[i];
    }
    key->port = port;
    #ifdef ENABLE_DST_IN_KEY
    key->dst_port = dst_port;

    for(size_t i; i<8;i++){
        (key->dst_addr)[i] = dst_addr[i];
    }
    #endif
}

void syntab_format_key(struct pep_proxy *proxy, struct syntab_key *key)
{
    for(size_t i; i<8;i++){
        (key->addr)[i] = proxy->src.addr[i];
    }
    key->port = proxy->src.port;
    #ifdef ENABLE_DST_IN_KEY
    key->dst_port = proxy->dst.port;
    for(size_t i; i<8;i++){
        (key->dst_addr)[i] = proxy->dst.addr[i];
    }
    #endif
}

struct pep_proxy *syntab_find(struct syntab_key *key)
{
    return hashtable_search(syntab.hash, key);
}

int syntab_add(struct pep_proxy *proxy)
{
    struct syntab_key *key;
    int ret;

    assert(proxy->status == PST_PENDING);
    key = calloc(sizeof(*key), 1);
    if (!key) {
        errno = ENOMEM;
        return -1;
    }

    syntab_make_key(key, proxy->src.addr, proxy->src.port, proxy->dst.port,proxy->dst.addr);
    ret = hashtable_insert(syntab.hash, key, proxy);
    if (ret == 0) {
        free(key);
        return -1;
    }

    list_add2tail(&syntab.conns, &proxy->lnode);
    syntab.num_items++;

    return 0;
}

void syntab_delete(struct pep_proxy *proxy)
{
    struct syntab_key key;

    syntab_make_key(&key, proxy->src.addr, proxy->src.port, proxy->dst.port,proxy->dst.addr);
    hashtable_remove(syntab.hash, &key);
    list_del(&proxy->lnode);
    syntab.num_items--;
}
