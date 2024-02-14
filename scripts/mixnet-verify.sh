#!/bin/bash

WORKSPACE_DIR=$1

if [ -z "${WORKSPACE_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

echo "***mixnet-verify..."

CLASSPATH="build/libs/egkmixnet-0.8-SNAPSHOT-all.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunVerifier \
    -egDir ${WORKSPACE_DIR}/eg \
    --inputBallots ${WORKSPACE_DIR}/bb/InputBallots.bin \
    --mixedDir ${WORKSPACE_DIR}/bb/mix1 \
    -width 34

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunVerifier \
    -egDir ${WORKSPACE_DIR}/eg \
    --inputBallots ${WORKSPACE_DIR}/bb/mix1/Shuffled.bin \
    --mixedDir ${WORKSPACE_DIR}/bb/mix2 \
    -width 34

echo " [DONE] Verifying mix1 and mix2 "
