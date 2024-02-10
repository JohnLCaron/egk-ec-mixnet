/*
     * Class:     com_verificatum_vmgj_VMG
     * Method:    spowm_naive
     * Signature: ([[B[[B[B)[B
     */
    JNIEXPORT jbyteArray JNICALL Java_com_verificatum_vmgj_VMG_spowmekg
    (JNIEnv *env, jclass clazz, jobjectArray javaBases,
     jobjectArray javaExponents, jbyteArray javaModulus)
    {

      int i;
      mpz_t *bases;
      mpz_t *exponents;
      mpz_t modulus;
      mpz_t result;

      jbyteArray javaResult;
      jbyteArray javaBase;
      jbyteArray javaExponent;

      /* Extract number of bases/exponents. */
      jsize numberOfBases = (*env)->GetArrayLength(env, javaBases);

      VMGJ_UNUSED(clazz);

      /* Convert exponents represented as array of byte[] to array of
         mpz_t. */
      bases = gmpmee_array_alloc(numberOfBases);
      for (i = 0; i < numberOfBases; i++)
        {
          javaBase = (jbyteArray)(*env)->GetObjectArrayElement(env, javaBases, i);
          jbyteArray_to_mpz_t(env, &(bases[i]), javaBase);
        }

      /* Convert exponents represented as array of byte[] to an array of
         mpz_t. */
      exponents = gmpmee_array_alloc(numberOfBases);
      for (i = 0; i < numberOfBases; i++)
        {
          javaExponent =
            (jbyteArray)(*env)->GetObjectArrayElement(env, javaExponents, i);
          jbyteArray_to_mpz_t(env, &(exponents[i]), javaExponent);
        }

      /* Convert modulus represented as a byte[] to a mpz_t. */
      jbyteArray_to_mpz_t(env, &modulus, javaModulus);

      /* Call our version of spowm. */
      mpz_init(result); // why not initialize in the egk_spowm call ?
      egk_spowm(result, bases, exponents, numberOfBases, modulus);

      /* Convert result back to a jbyteArray. */
      mpz_t_to_jbyteArray(env, &javaResult, result);

      /* Deallocate resources. */
      mpz_clear(result);
      mpz_clear(modulus);
      gmpmee_array_clear_dealloc(exponents, numberOfBases);
      gmpmee_array_clear_dealloc(bases, numberOfBases);

      return javaResult;
    }

  /*
     * Class:     com_verificatum_vmgj_VMG
     * Method:    spowm_naive
     * Signature: ([[B[[B[B)[B
     */
    JNIEXPORT jbyteArray JNICALL Java_com_verificatum_vmgj_VMG_spowmnaive
    (JNIEnv *env, jclass clazz, jobjectArray javaBases,
     jobjectArray javaExponents, jbyteArray javaModulus)
    {

      int i;
      mpz_t *bases;
      mpz_t *exponents;
      mpz_t modulus;
      mpz_t result;

      jbyteArray javaResult;
      jbyteArray javaBase;
      jbyteArray javaExponent;

      /* Extract number of bases/exponents. */
      jsize numberOfBases = (*env)->GetArrayLength(env, javaBases);

      VMGJ_UNUSED(clazz);

      /* Convert exponents represented as array of byte[] to array of
         mpz_t. */
      bases = gmpmee_array_alloc(numberOfBases);
      for (i = 0; i < numberOfBases; i++)
        {
          javaBase = (jbyteArray)(*env)->GetObjectArrayElement(env, javaBases, i);
          jbyteArray_to_mpz_t(env, &(bases[i]), javaBase);
        }

      /* Convert exponents represented as array of byte[] to an array of
         mpz_t. */
      exponents = gmpmee_array_alloc(numberOfBases);
      for (i = 0; i < numberOfBases; i++)
        {
          javaExponent =
            (jbyteArray)(*env)->GetObjectArrayElement(env, javaExponents, i);
          jbyteArray_to_mpz_t(env, &(exponents[i]), javaExponent);
        }

      /* Convert modulus represented as a byte[] to a mpz_t. */
      jbyteArray_to_mpz_t(env, &modulus, javaModulus);

      /* Call GMP's exponentiated product function. */
      mpz_init(result);
      gmpmee_spowm_naive(result, bases, exponents, numberOfBases, modulus);

      /* Convert result to a jbyteArray. */
      mpz_t_to_jbyteArray(env, &javaResult, result);

      /* Deallocate resources. */
      mpz_clear(result);
      mpz_clear(modulus);
      gmpmee_array_clear_dealloc(exponents, numberOfBases);
      gmpmee_array_clear_dealloc(bases, numberOfBases);

      return javaResult;
    }

/*
     * Class:     com_verificatum_vmgj_VMG
     * Method:    mulmod_naive
     * Signature: ([[B[[B[B)[B
     */
    JNIEXPORT jbyteArray JNICALL Java_com_verificatum_vmgj_VMG_mulmodnaive
    (JNIEnv *env, jclass clazz, jobjectArray javaBases, jbyteArray javaModulus)
    {

      int i;
      mpz_t *bases;
      mpz_t modulus;
      mpz_t result;

      jbyteArray javaResult;
      jbyteArray javaBase;

      /* Extract number of bases/exponents. */
      jsize numberOfBases = (*env)->GetArrayLength(env, javaBases);

      VMGJ_UNUSED(clazz);

      /* Convert bases represented as array of byte[] to array of mpz_t. */
      bases = gmpmee_array_alloc(numberOfBases);
      for (i = 0; i < numberOfBases; i++)
        {
          javaBase = (jbyteArray)(*env)->GetObjectArrayElement(env, javaBases, i);
          jbyteArray_to_mpz_t(env, &(bases[i]), javaBase);
        }

      /* Convert modulus represented as a byte[] to a mpz_t. */
      jbyteArray_to_mpz_t(env, &modulus, javaModulus);

      /* Call GMP's exponentiated product function. */
      mpz_init(result);
      gmpmee_mulmod_naive(result, bases, numberOfBases, modulus);

      /* Convert result to a jbyteArray. */
      mpz_t_to_jbyteArray(env, &javaResult, result);

      /* Deallocate resources. */
      mpz_clear(result);
      mpz_clear(modulus);
      gmpmee_array_clear_dealloc(bases, numberOfBases);

      return javaResult;
    }