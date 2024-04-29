#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No public workspace provided."
    exit 1
fi

echo ""
echo "***mixnet-verify..."

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.cli.RunProofOfShuffleVerifier \
    -publicDir ${PUBLIC_DIR} \
    --outputMixDir ${PUBLIC_DIR}/mix1

retval1=$?

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.cli.RunProofOfShuffleVerifier \
    -publicDir ${PUBLIC_DIR} \
    --inputMixDir ${PUBLIC_DIR}/mix1 \
    --outputMixDir ${PUBLIC_DIR}/mix2

retval2=$?

echo " [DONE] Verifying mix1 retval=$retval1 and mix2 retval=$retval2"
