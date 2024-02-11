#include <stdlib.h>
#include <string.h>
#include <gmp.h>

// Product (pa * pb) modulo
void
egk_mulMod(void *result, const void *pb1, const void *pb2, const void *modulusBytes, size_t nbytes) {
    mpz_t modulus, p1, p2, product;
    size_t count;

    // void mpz_import (mpz_ptr z, size_t count, int order, size_t size, int endian, size_t nail, const void *data)
    mpz_init(modulus);
    mpz_import(modulus, nbytes, 1, 1, 1, 0, modulusBytes);

    mpz_init(p1);
    mpz_import(p1, nbytes, 1, 1, 1, 0, pb1);

    mpz_init(p2);
    mpz_import(p2, nbytes, 1, 1, 1, 0, pb2);

    mpz_init(product);
    mpz_mul(product, p1, p2);
    mpz_mod(product, product, modulus);

    // void * mpz_export (void *data, size_t *countp, int order, size_t size, int endian, size_t nail, mpz_srcptr z)
    __gmpz_export(result, &count, 1, 1, 1, 0, product);

   /* Deallocate resources. */
    mpz_clear(product);
    mpz_clear(p2);
    mpz_clear(p1);
    mpz_clear(modulus);
}

// Product (pb) modulo
void
egk_mulModA(void *result, const void **pb, const int len, const void *modulusBytes, size_t nbytes) {
    mpz_t modulus, product;
    mpz_t tmp;
    size_t count;
    int i;

    // void mpz_import (mpz_ptr z, size_t count, int order, size_t size, int endian, size_t nail, const void *data)
    mpz_init(modulus);
    mpz_import(modulus, nbytes, 1, 1, 1, 0, modulusBytes);

    mpz_init(tmp);
    mpz_init(product);
    mpz_set_ui(product, 1);

    for (i=0; i<len; i++) {
        mpz_import(tmp, nbytes, 1, 1, 1, 0, *pb);
        mpz_mul(product, product, tmp);
        mpz_mod(product, product, modulus);
        pb++;
    }

    // void * mpz_export (void *data, size_t *countp, int order, size_t size, int endian, size_t nail, mpz_srcptr z)
    __gmpz_export(result, &count, 1, 1, 1, 0, product);

   /* Deallocate resources. */
    mpz_clear(product);
    mpz_clear(tmp);
    mpz_clear(modulus);
}

// pb^pa modulo, component-wise
void
egk_powmA(void *result, const void **pb, const void **qb, const int len, const void *modulusBytes, size_t pbytes, size_t qbytes) {
    mpz_t mzp_modulus, mzp_base, mzp_exp, mzp_rop;
    void *resultBytes;
    size_t count;
    int i;
    int offset;

    mpz_init(mzp_modulus);
    mpz_import(mzp_modulus, pbytes, 1, 1, 1, 0, modulusBytes);

    mpz_init(mzp_base);
    mpz_init(mzp_exp);
    mpz_init(mzp_rop);
    resultBytes = malloc(pbytes);

    for (i=0; i<len; i++) {
        mpz_import(mzp_base, pbytes, 1, 1, 1, 0, *pb);
        mpz_import(mzp_exp, qbytes, 1, 1, 1, 0, *qb);

        // mpz_powm (mpz_ptr r, mpz_srcptr b, mpz_srcptr e, mpz_srcptr m)
        mpz_powm(mzp_rop, mzp_base, mzp_exp, mzp_modulus);

        // theres no guarentee mzp_rop is 512 bytes long. need a normalizer.
        __gmpz_export(resultBytes, &count, 1, 1, 1, 0, mzp_rop);
        offset = 512 - count;
        if (offset >= 0) { // should barf ??
            memcpy(result+offset, resultBytes, count);
        }

        pb++;
        qb++;
        result += pbytes;
    }

   /* Deallocate resources. */
    free(resultBytes);
    mpz_clear(mzp_modulus);
    mpz_clear(mzp_base);
    mpz_clear(mzp_exp);
    mpz_clear(mzp_rop);
}
