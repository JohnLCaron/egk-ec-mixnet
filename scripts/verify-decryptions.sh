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
echo "*** verify decryptions: verify decrypted serial numbers and ballots"

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.cli.RunVerifyDecryptions \
    -publicDir ${PUBLIC_DIR} \
    -dballots ${PRIVATE_DIR}/decrypted_ballots \
    -pballots ${PRIVATE_DIR}/input_ballots \
    --show

echo "   [DONE] verified decrypted ballots"
