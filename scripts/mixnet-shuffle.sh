#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    rave_print "No public workspace provided."
    exit 1
fi

echo ""
echo "***mixnet-shuffle and proof..."

CLASSPATH="build/libs/egkmixnet-0.84-SNAPSHOT-all.jar"

mkdir -p  ${PUBLIC_DIR}/mix1
mkdir -p  ${PUBLIC_DIR}/mix2

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunMixnet \
    -egDir ${PUBLIC_DIR} \
    -eballots ${PUBLIC_DIR}/encryptedBallots \
    -width 34 \
    --outputDir ${PUBLIC_DIR}/mix1/ \
    --mixName mix1

echo "  mixnet-shuffle and proof written to ${PUBLIC_DIR}/mix1"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunMixnet \
    -egDir ${PUBLIC_DIR} \
    --inputBallots ${PUBLIC_DIR}/mix1/Shuffled.bin \
    -width 34 \
    --outputDir ${PUBLIC_DIR}/mix2/ \
    --mixName mix2

echo "  [DONE] mixnet-shuffle and proof written to ${PUBLIC_DIR}/mix2"