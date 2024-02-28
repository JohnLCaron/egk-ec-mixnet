#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    rave_print "No public workspace provided."
    exit 1
fi

echo ""
echo "*** Verifying ElectionGuard record ..."

CLASSPATH="build/libs/egkmixnet-2.1-SNAPSHOT-all.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.eg.cli.RunVerifier \
    -in ${PUBLIC_DIR}

echo "   [DONE] Verifying ElectionGuard record in ${PUBLIC_DIR}"
