/**
 * @brief Manipulate integers atomically
 */


#ifndef __ATOMIC_H
#define __ATOMIC_H

#ifndef __GNUC__
#error "Atomic operations require GCC compiler!"
#endif /* !GCC */


/**
 * @struct atomic_t
 * @brief Encapsulate access to an atomic integer
 */
typedef struct __atomic {
    volatile int val;
} atomic_t;


/**
 * @brief Return the value store in the atomic variable
 * @param a - the atomic variable
 */
#define atomic_read(a) ((a)->val)


/**
 * @brief Store a new value in the atomic variable
 * @param a - the atomic variable
 * @param b - the value to store
 */
#define atomic_set(a, b) ((a)->val = b)


/**
 * @brief Increment the value stored in an atomic variable by 1
 * @param a - the atomic variable
 */
static inline int atomic_inc(atomic_t* a)
{
    return __sync_fetch_and_add(&a->val, 1);
}


/**
 * @brief Decrement the value stored in an atomic variable by 1
 * @param a - the atomic variable
 */
static inline int atomic_dec(atomic_t* a)
{
    return __sync_fetch_and_sub(&a->val, 1);
}


/**
 * @brief Apply a binary AND mask to an atomic variable
 * @param a - the atomic variable
 * @param mask - the mask to AND with
 */
static inline int atomic_and(atomic_t* a, int mask)
{
    return __sync_fetch_and_and(&a->val, mask);
}


/**
 * @brief Apply a binary OR mask to an atomic variable
 * @param a - the atomic variable
 * @param mask - the mask to OR with
 */
static inline int atomic_or(atomic_t* a, int mask)
{
    return __sync_fetch_and_or(&a->val, mask);
}


#endif /* __ATOMIC_H */
