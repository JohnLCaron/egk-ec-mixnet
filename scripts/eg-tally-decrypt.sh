#!/bin/bash

PUBLIC_DIR=$1
PRIVATE_DIR=$2

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No public workspace provided."
    exit 1
fi

if [ -z "${PRIVATE_DIR}" ]; then
    echo "No private workspace provided."
    exit 1
fi

echo ""
echo "*** Decrypting electionguard tally..."

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.eg.cli.RunTrustedTallyDecryption \
    -in ${PUBLIC_DIR} \
    -trustees ${PRIVATE_DIR}/trustees \
    -out ${PUBLIC_DIR}

retval=$?

echo "   [DONE] Decrypted electionguard tally into ${PUBLIC_DIR}/tally.json returns $retval"
