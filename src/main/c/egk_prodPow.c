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
#include <gmp.h>

typedef struct {
  int width;              /**< Number of bases/exponents in each block. */
  mpz_t *pproduct;            /**< Table of partial products */
  size_t npproduct;         /**< size of partial product table. */
} egk_prod_table[1]; /* Magic references. */

void
egk_table_init(egk_prod_table table, int nrows, int width)  {
  size_t j;

  table->width = width;
  if (nrows < width) {
     table->width = nrows;
  }
  table->npproduct = 1 << width;  /* Size of a subtable = 128. */

  /* Allocate and initialize partial product tables. */
  table->pproduct = (mpz_t *) malloc(table->npproduct * sizeof(mpz_t));
  for (j = 0; j < table->npproduct; j++) {
  	 mpz_init( table->pproduct[j] );
  }
}

void
egk_table_free(egk_prod_table table)  {
  size_t j;
  for (j = 0; j < table->npproduct; j++) {
      mpz_clear(table->pproduct[j]);
  }
  free(table->pproduct);
}

void
egk_table_precomp(egk_prod_table table, mpz_t *bases, size_t block_width, mpz_t modulus) {
  size_t j;
  int mask;
  int one_mask;
  mpz_t *t;

  t = table->pproduct;

  /* Initialize all trivial products. */
  mpz_set_ui(t[0], 1);
  mask = 1;
  for (j = 0; j < block_width; j++) {
      mpz_set(t[mask], bases[j]);
      mask <<= 1;
  }

  /* Initialize all non-trivial products. */
  for (mask = 1; mask < (1 << block_width); mask++) {
      one_mask = mask & (-mask);
      mpz_mul(t[mask], t[mask ^ one_mask], t[one_mask]);
      mpz_mod(t[mask], t[mask], modulus);
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
egk_table_compute(mpz_t rop, egk_prod_table table, mpz_t *exponents, size_t block_width, mpz_t modulus) {
  size_t i;
  int index;
  int mask;
  size_t bitlen;
  size_t max_exponent_bitlen;

  /* Compute the maximal bit length among the exponents.*/
  max_exponent_bitlen = 0;
  for (i = 0; i < block_width; i++) {
    bitlen = mpz_sizeinbase(exponents[i], 2);
    if (bitlen > max_exponent_bitlen) {
        max_exponent_bitlen = bitlen;
    }
  }

  /* Initialize result variable. */
  mpz_set_ui(rop, 1);

  /* Execute simultaneous square-and-multiply. */
  for (index = max_exponent_bitlen - 1; index >= 0; index--) {
      /* Square ... */
      mpz_mul(rop, rop, rop);
      mpz_mod(rop, rop, modulus);

      /* ... and multiply. */
      mask = egk_getbits(exponents, index, block_width);
      mpz_mul(rop, rop, table->pproduct[mask]);
      mpz_mod(rop, rop, modulus);
    }
}

// rewrite just doing one batch at a time. not as fast, but less memory.
void
egk_prodPow(void *result, const void **pb, const void **qb, const int nrows, const void *modulusBytes, size_t pbytes, size_t qbytes) {
    mpz_t modulus;
    mpz_t *bases;
    mpz_t *exponents;
    mpz_t rop, batch_rop;
    egk_prod_table table;

    void *resultBytes;
    size_t count;
    int starting_row, offset;
    int i;

    int width = 7;

    mpz_init(modulus);
    __gmpz_import(modulus, pbytes, 1, 1, 1, 0, modulusBytes);

    exponents = malloc(width * sizeof(mpz_t));
    bases = malloc(width * sizeof(mpz_t));
    for (i=0; i<width; i++) {
        mpz_init(bases[i]);
        mpz_init(exponents[i]);
    }

    // initialize table to do width exps at a time
    egk_table_init(table, nrows, width);

    mpz_init(rop);
    mpz_set_ui(rop, 1);
    mpz_init(batch_rop);

    for (starting_row = 0; starting_row < nrows; starting_row += width) {
        int batch_width = (starting_row + width > nrows) ? nrows - starting_row : width;

        // just bring in width at a time
        for (i=0; i<batch_width; i++) {
           mpz_init(exponents[i]);
           mpz_init(bases[i]);

           mpz_import(exponents[i], qbytes, 1, 1, 1, 0, *qb);
           mpz_import(bases[i], pbytes, 1, 1, 1, 0, *pb);
           qb++;
           pb++;
        }

      /* Perform computation for batch */
      egk_table_precomp(table, bases, batch_width, modulus);

      /* Compute batch. */
      egk_table_compute(batch_rop, table, exponents, batch_width, modulus);

      /* Multiply with running total (rop). */
      mpz_mul(rop, rop, batch_rop);
      mpz_mod(rop, rop, modulus);
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

    /* Deallocate resources. */
    for (i=0; i<width; i++) {
      mpz_clear(exponents[i]);
      mpz_clear(bases[i]);
    }
    free(exponents);
    free(bases);
    free(resultBytes);

    egk_table_free(table);

    mpz_clear(modulus);
    mpz_clear(rop);
    mpz_clear(batch_rop);
}
