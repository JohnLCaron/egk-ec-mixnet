#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No public workspace provided."
    exit 1
fi

echo ""
echo "*** Verifying ElectionGuard record ..."

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.eg.cli.RunVerifier \
    -in ${PUBLIC_DIR}

retval=$?

echo "   [DONE] Verifying ElectionGuard record in ${PUBLIC_DIR} returns $retval"
