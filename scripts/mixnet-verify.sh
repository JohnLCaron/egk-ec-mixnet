#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    rave_print "No public workspace provided."
    exit 1
fi

echo ""
echo "***mixnet-verify..."

CLASSPATH="build/libs/egkmixnet-2.1-SNAPSHOT-all.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunVerifier \
    -publicDir ${PUBLIC_DIR} \
    -eballots ${PUBLIC_DIR}/encryptedBallots \
    --mixDir ${PUBLIC_DIR}/mix1

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunVerifier \
    -publicDir ${PUBLIC_DIR} \
    --inputBallotFile ${PUBLIC_DIR}/mix1/Shuffled.bin \
    --mixDir ${PUBLIC_DIR}/mix2

echo " [DONE] Verifying mix1 and mix2 "
