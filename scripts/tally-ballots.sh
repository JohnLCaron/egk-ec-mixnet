#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

echo ""
echo "*** Tallying encrypted ballots..."

CLASSPATH="build/libs/egkmixnet-2.1-SNAPSHOT-all.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.eg.cli.RunAccumulateTally \
    -in ${PUBLIC_DIR} \
    -eballots ${PUBLIC_DIR}/encrypted_ballots/device42 \
    -out ${PUBLIC_DIR}

echo "   [DONE] Tallying encrypted ballots."
