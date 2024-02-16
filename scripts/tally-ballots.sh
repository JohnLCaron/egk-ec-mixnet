#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

echo ""
echo "*** Tallying encrypted ballots..."

CLASSPATH="build/libs/egkmixnet-0.8-SNAPSHOT-all.jar"

java -classpath $CLASSPATH \
  electionguard.cli.RunAccumulateTally \
    -in ${PUBLIC_DIR} \
    -eballots ${PUBLIC_DIR}/encryptedBallots \
    -out ${PUBLIC_DIR}

echo "   [DONE] Tallying encrypted ballots."
