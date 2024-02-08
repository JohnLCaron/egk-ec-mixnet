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
#include <gmp.h>
#include "gmpmee.h"

void
egk_spowm_init(gmpmee_spowm_tab table, size_t len, mpz_t modulus, size_t block_width)  {
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
egk_spowm_precomp(gmpmee_spowm_tab table, mpz_t *bases) {
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
egk_spowm_table(mpz_t rop, gmpmee_spowm_tab table, mpz_t *exponents) {
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
egk_spowm(mpz_t rop, mpz_t *bases, mpz_t *exponents, size_t len, mpz_t modulus) {
  size_t batch_len = len; // HEY only one batch ?? wtf ??
  size_t block_width = 7;

  size_t i;
  gmpmee_spowm_tab table;  // declared in gmpmee.h
  mpz_t tmp;

  mpz_init(tmp);

  // initialize table, it is reused for each batch ??
  egk_spowm_init(table, batch_len, modulus, block_width);

  mpz_set_ui(rop, 1);
  for (i = 0; i < len; i += batch_len) { /// hmmm, batch_len == len wtf?
      /* Perform computation for batch */
      egk_spowm_precomp(table, bases);

      /* Compute batch. */
      egk_spowm_table(tmp, table, exponents);

      /* Multiply with result so far. */
      mpz_mul(rop, rop, tmp);
      mpz_mod(rop, rop, modulus);

      /* Move on to next batch. */
      bases += batch_len;
      exponents += batch_len;
    }
  mpz_clear(tmp);
  gmpmee_spowm_clear(table);
}
