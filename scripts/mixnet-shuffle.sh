#!/bin/bash

WORKSPACE_DIR=$1

if [ -z "${WORKSPACE_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

echo "***mixnet-shuffle and proof..."

CLASSPATH="build/libs/egkmixnet-0.8-SNAPSHOT-all.jar"

mkdir -p  ${WORKSPACE_DIR}/bb
mkdir -p  ${WORKSPACE_DIR}/bb/mix1
mkdir -p  ${WORKSPACE_DIR}/bb/mix2

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunMixnet \
    -egDir ${WORKSPACE_DIR}/eg \
    -eballots ${WORKSPACE_DIR}/bb/encryptedBallots \
    -width 34 \
    --outputDir ${WORKSPACE_DIR}/bb/ \
    --mixName mix1

echo "  mixnet-shuffle and proof written to ${WORKSPACE_DIR}/bb/mix1"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunMixnet \
    -egDir ${WORKSPACE_DIR}/eg \
    --inputBallots ${WORKSPACE_DIR}/bb/mix1/Shuffled.bin \
    -width 34 \
    --outputDir ${WORKSPACE_DIR}/bb/ \
    --mixName mix2

echo "  [DONE] mixnet-shuffle and proof written to ${WORKSPACE_DIR}/bb/mix2"