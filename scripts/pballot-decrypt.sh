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
echo "*** pballot-decrypt: decrypt specified paper ballot"

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.cli.RunPaperBallotDecrypt \
    -publicDir ${PUBLIC_DIR} \
    -psn random \
    -trustees ${PRIVATE_DIR}/trustees \
    --mixDir ${PUBLIC_DIR}/mix2 \
    -out ${PRIVATE_DIR}/decrypted_ballots

echo "   [DONE] Decrypted paper ballot into${PRIVATE_DIR}/decrypted_ballots/"
