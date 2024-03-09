#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No workspace provided."
    exit 1
fi

echo ""
echo "*** Tallying encrypted ballots..."

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.eg.cli.RunAccumulateTally \
    -in ${PUBLIC_DIR} \
    -eballots ${PUBLIC_DIR}/encrypted_ballots \
    -out ${PUBLIC_DIR}

echo "   [DONE] Tallying encrypted ballots."
