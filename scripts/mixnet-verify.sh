#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    rave_print "No public workspace provided."
    exit 1
fi

echo ""
echo "***mixnet-verify..."

CLASSPATH="build/libs/egkmixnet-0.84-SNAPSHOT-all.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunVerifier \
    -egDir ${PUBLIC_DIR} \
    -eballots ${PUBLIC_DIR}/encryptedBallots \
    --mixedDir ${PUBLIC_DIR}/mix1 \
    -width 34

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunVerifier \
    -egDir ${PUBLIC_DIR} \
    --inputBallots ${PUBLIC_DIR}/mix1/Shuffled.bin \
    --mixedDir ${PUBLIC_DIR}/mix2 \
    -width 34

echo " [DONE] Verifying mix1 and mix2 "
