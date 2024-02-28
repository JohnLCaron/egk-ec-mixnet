#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    rave_print "No public workspace provided."
    exit 1
fi

echo ""
echo "***mixnet-shuffle and proof..."

CLASSPATH="build/libs/egkmixnet-2.1-SNAPSHOT-all.jar"

mkdir -p  ${PUBLIC_DIR}/mix1
mkdir -p  ${PUBLIC_DIR}/mix2

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunMixnet \
    -publicDir ${PUBLIC_DIR} \
    -eballots ${PUBLIC_DIR}/encrypted_ballots/device42 \
    --mixName mix1

echo "  mixnet-shuffle and proof written to ${PUBLIC_DIR}/mix1"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunMixnet \
    -publicDir ${PUBLIC_DIR} \
    -eballots ${PUBLIC_DIR}/encrypted_ballots/device42 \
    --inputBallotFile ${PUBLIC_DIR}/mix1/Shuffled.bin \
    --mixName mix2

echo "  [DONE] mixnet-shuffle and proof written to ${PUBLIC_DIR}/mix2"