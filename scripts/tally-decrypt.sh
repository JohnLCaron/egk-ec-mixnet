#!/bin/bash

PUBLIC_DIR=$1
PRIVATE_DIR=$2

if [ -z "${PUBLIC_DIR}" ]; then
    rave_print "No public workspace provided."
    exit 1
fi

if [ -z "${PRIVATE_DIR}" ]; then
    rave_print "No private workspace provided."
    exit 1
fi

echo ""
echo "*** Decrypting encrypted tally..."

CLASSPATH="build/libs/egkmixnet-0.84-SNAPSHOT-all.jar"

java -classpath $CLASSPATH \
  electionguard.cli.RunTrustedTallyDecryption \
    -in ${PUBLIC_DIR} \
    -trustees ${PRIVATE_DIR}/trustees \
    -out ${PUBLIC_DIR}

echo "   [DONE] Decrypted tally in ${PUBLIC_DIR}/tally.json"
