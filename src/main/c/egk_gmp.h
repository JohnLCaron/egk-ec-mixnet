#ifndef EGK_SPOWM_H
#define EGK_SPOWM_H

#include <gmp.h>

// Product ( bases^exp ) modulo
// Douglas Wikstrom version of prodPow, running about 50% faster, but uses more memory.
void egk_prodPowW(void *result, const void **pb, const void **qb, const int len, const void *modulusBytes, size_t pbytes, size_t qbytes);
// standard version, memory use is bounded.
void egk_prodPow(void *result, const void **pb, const void **qb, const int nrows, const void *modulusBytes, size_t pbytes, size_t qbytes);

// (pb1 * pb2) modulo
void egk_mulMod(void *result, const void *pb1, const void *pb2, const void *modulusBytes, size_t nbytes);

// Prod (pb modulo)
void egk_mulModA(void *result, const void **pb, const int len, const void *modulusBytes, size_t nbytes);

// array of (pb ^ pa) modulo
void egk_powmA(void *result, const void **pb, const void **qb, const int len, const void *modulusBytes, size_t pbytes, size_t qbytes);


#endif /* EGK_SPOWM_H */
