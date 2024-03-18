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
  org.cryptobiotic.mixnet.cli.RunVerifier \
    -publicDir ${PUBLIC_DIR} \
    -eballots ${PUBLIC_DIR}/encrypted_ballots \
    --outputMixDir ${PUBLIC_DIR}/mix1

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.cli.RunVerifier \
    -publicDir ${PUBLIC_DIR} \
    --inputMixDir ${PUBLIC_DIR}/mix1 \
    --outputMixDir ${PUBLIC_DIR}/mix2

echo " [DONE] Verifying mix1 and mix2 "
