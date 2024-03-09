#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No public workspace provided."
    exit 1
fi

echo ""
echo "***mixnet-shuffle and proof..."

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

mkdir -p  ${PUBLIC_DIR}/mix1
mkdir -p  ${PUBLIC_DIR}/mix2

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunMixnet \
    -publicDir ${PUBLIC_DIR} \
    -eballots ${PUBLIC_DIR}/encrypted_ballots \
    --mixName mix1

echo "  mixnet-shuffle and proof written to ${PUBLIC_DIR}/mix1"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunMixnet \
    -publicDir ${PUBLIC_DIR} \
    -eballots ${PUBLIC_DIR}/encrypted_ballots \
    --inputBallotFile ${PUBLIC_DIR}/mix1/Shuffled.bin \
    --mixName mix2

echo "  [DONE] mixnet-shuffle and proof written to ${PUBLIC_DIR}/mix2"