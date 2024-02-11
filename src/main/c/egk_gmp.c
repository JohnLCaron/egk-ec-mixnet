/*
 * Copyright 2008 2009 2010 2011 2013 2014 2015 2016 Douglas Wikstrom
 *
 * This file is part of GMP Modular Exponentiation Extension (GMPMEE).
 *
 * GMPMEE is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GMPMEE is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GMPMEE. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mcheck.h>
#include <gmp.h>

/**
 * Stores the tables of precomputed products of subsets of the
 * bases. Each table contains the precomputed products for a range of
 * a given width of the bases.
 */
typedef struct {
  size_t len;             /**< Total number of bases/exponents. */
  size_t block_width;     /**< Number of bases/exponents in each block. */
  size_t tabs_len;        /**< Number of blocks. */
  mpz_t **tabs;           /**< Table of tables, one sub-table for each block. */
  mpz_t modulus;          /**< Modulus used in computations. */

} egk_spowm_tab[1]; /* Magic references. */

void
egk_spowm_init(egk_spowm_tab table, size_t len, mpz_t modulus, size_t block_width)  {
  size_t i, j;
  mpz_t *t;        /* Temporary variable for subtable. */
  size_t tab_len = 1 << block_width;  /* Size of a subtable = 128. */

  table->len = len;
  table->block_width = block_width;
  if (len < block_width) {
    table->block_width = len;
  }
  table->tabs_len = (len + block_width - 1) / block_width;

  mpz_init(table->modulus);
  mpz_set(table->modulus, modulus);

  /* Allocate and initialize space for pointers to tables. */
  table->tabs = (mpz_t **)malloc(table->tabs_len * sizeof(mpz_t *));

  for (i = 0; i < table->tabs_len; i++) {
    /* Last block may be more narrow than the other, but they are never zero. */
    if (i == table->tabs_len - 1 && len - (table->tabs_len - 1) * block_width < block_width) {
	  block_width = len - (table->tabs_len - 1) * block_width;
	  tab_len = 1 << block_width;
	}

    /* Allocate and initialize a table. */
    table->tabs[i] = (mpz_t *) malloc(tab_len * sizeof(mpz_t));
    t = table->tabs[i];

    /* Initialize mpz_t's. */
    for (j = 0; j < tab_len; j++) {
	  mpz_init(t[j]);
	}
  }
}

void
egk_spowm_precomp(egk_spowm_tab table, mpz_t *bases) {
  size_t i, j;
  size_t tabs_len = table->tabs_len;
  size_t block_width = table->block_width;
  int mask;
  int one_mask;
  mpz_t *t;

  for (i = 0; i < tabs_len; i++) {
      /* Last block may have smaller width, but it is never zero. */
      if (i == tabs_len - 1) {
          block_width = table->len - (tabs_len - 1) * block_width;
      }

      /* Current subtable. */
      t = table->tabs[i];

      /* Initialize current subtable with all trivial products. */
      mpz_set_ui(t[0], 1);

      mask = 1;
      for (j = 0; j < block_width; j++) {
          mpz_set(t[mask], bases[j]);
          mask <<= 1;
      }

      /* Initialize current subtable with all non-trivial products. */
      for (mask = 1; mask < (1 << block_width); mask++) {
          one_mask = mask & (-mask);
          mpz_mul(t[mask], t[mask ^ one_mask], t[one_mask]);
          mpz_mod(t[mask], t[mask], table->modulus);
      }

      bases += block_width; // pointers, so cool
    }
}

/*
 * Returns the index'th bit of each of the first block_width integers
 * in the array. The least significant bit in the output is the bit
 * extracted from the first integer in the input array.
 */
static int
egk_getbits(mpz_t *op, int index, size_t block_width)
{
  int i;
  int bits = 0;

  for (i = block_width - 1; i >= 0; i--) {
      bits <<= 1;
      if (mpz_tstbit(op[i], index)) {
	  bits |= 1;
	}
  }
  return bits;
}

void
egk_spowm_table(mpz_t rop, egk_spowm_tab table, mpz_t *exponents) {
  size_t i;
  int index;
  int mask;
  size_t bitlen;
  mpz_t *exps;
  size_t max_exponent_bitlen;

  size_t len = table->len;
  size_t tabs_len = table->tabs_len;
  size_t block_width = table->block_width;
  size_t last_block_width = len - (tabs_len - 1) * block_width;
  mpz_t **tabs = table->tabs;

  /* Compute the maximal bit length among the exponents. */
  max_exponent_bitlen = 0;
  for (i = 0; i < len; i++) {
    bitlen = mpz_sizeinbase(exponents[i], 2);
    if (bitlen > max_exponent_bitlen) {
        max_exponent_bitlen = bitlen;
    }
  }

  /* Initialize result variable. */
  mpz_set_ui(rop, 1);

  /* Execute simultaneous square-and-multiply. */
  for (index = max_exponent_bitlen - 1; index >= 0; index--) {
      // When processing the batch, all squarings are done for the complete batch
      /* Square ... */
      mpz_mul(rop, rop, rop);
      mpz_mod(rop, rop, table->modulus);

      /* ... and multiply. */
      i = 0;
      exps = exponents;
      while (i < tabs_len) {
          if (i == tabs_len - 1) {
              mask = egk_getbits(exps, index, last_block_width);
          } else {
              /* This is never executed if there is a single table. */
              mask = egk_getbits(exps, index, block_width);
          }

          mpz_mul(rop, rop, tabs[i][mask]);
          mpz_mod(rop, rop, table->modulus);
          i++;
          exps += block_width;
      }
    }
}

void
egk_spowm_clear(egk_spowm_tab table) {
  size_t i, j;
  mpz_t *t;
  size_t tabs_len = table->tabs_len;
  size_t block_width = table->block_width;
  size_t tab_len = 1 << block_width;

  for (i = 0; i < tabs_len; i++) {
      /* Last block may have smaller width, but it is never zero. */
      if (i == tabs_len - 1) {
          block_width = table->len - (tabs_len - 1) * block_width;
          tab_len = 1 << block_width;
      }

      /* Deallocate all integers in table. */
      t = table->tabs[i];
      for (j = 0; j < tab_len; j++) {
          mpz_clear(t[j]);
      }

      /* Deallocate table. */
      free(t);
  }

  /* Deallocate table of tables. */
  free(table->tabs);

  mpz_clear(table->modulus);
}

void
egk_prodPowA(void *result, const char **pb, const char **qb, const int len, const void *modulusBytes, size_t pbytes, size_t qbytes) {
    mpz_t modulus, rop;
    mpz_t tmp;
    mpz_t *bases, *basep;
    mpz_t *exponents, *expp;
    void * resultBytes;
    size_t count;
    int i, offset;

    size_t batch_len = len; // HEY only one batch ?? wtf ??
    size_t block_width = 7;

    egk_spowm_tab table;

    mpz_init(modulus);
    mpz_import(modulus, pbytes, 1, 1, 1, 0, modulusBytes);

    exponents = malloc(len * sizeof(mpz_t)); // LOOK at other example above
    for (i=0; i<len; i++) {
        mpz_init(exponents[i]);
        mpz_import(exponents[i], qbytes, 1, 1, 1, 0, *qb);
        //printf(" qb first byte = %d\n", *qb[0]);
        qb++;
    }

    bases = malloc(len * sizeof(mpz_t)); // can probably get this down to 7
    for (i=0; i<len; i++) {
        mpz_init(bases[i]);
        mpz_import(bases[i], pbytes, 1, 1, 1, 0, *pb);
        //printf(" pb first byte = %d\n", *pb[0]);
        pb++;
    }

    // initialize table, it is reused for each batch ??
    egk_spowm_init(table, batch_len, modulus, block_width);
    //printf("egk_spowm_init\n");

    mpz_init(tmp);
    mpz_init(rop);
    mpz_set_ui(rop, 1);

    expp = exponents;
    basep = bases;
    for (i = 0; i < len; i += batch_len) { /// hmmm, batch_len == len wtf?
      /* Perform computation for batch */
      egk_spowm_precomp(table, basep);

      /* Compute batch. */
      egk_spowm_table(tmp, table, expp);

      /* Multiply with result so far. */
      mpz_mul(rop, rop, tmp);
      mpz_mod(rop, rop, modulus);

      /* Move on to next batch. */
      basep += batch_len;
      expp += batch_len;
    }

    // theres no guarentee rop is 512 bytes long. need a normalizer.
    resultBytes = malloc(pbytes);
    __gmpz_export(resultBytes, &count, 1, 1, 1, 0, rop);
    offset = 512 - count;
    if (offset >= 0) {
        memcpy(result+offset, resultBytes, count);
    } else {
        printf("__gmpz_export bytes > 512 \n");
    }

    // Deallocate resources.
    mpz_clear(modulus);

    egk_spowm_clear(table);

    mpz_clear(rop);
    mpz_clear(tmp);

    for (i=0; i<len; i++) {
      mpz_clear(exponents[i]);
      mpz_clear(bases[i]);
    }
    free(exponents);
    free(bases);
    free(resultBytes);

}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
