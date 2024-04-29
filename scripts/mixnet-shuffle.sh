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
  org.cryptobiotic.mixnet.cli.RunMixnet \
    -publicDir ${PUBLIC_DIR} \
    --mixName mix1

retval=$?

echo "  mixnet-shuffle and proof written to ${PUBLIC_DIR}/mix1 retval=$retval"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.cli.RunMixnet \
    -publicDir ${PUBLIC_DIR} \
    --inputMixDir ${PUBLIC_DIR}/mix1 \
    --mixName mix2

retval=$?

echo "  [DONE] mixnet-shuffle and proof written to ${PUBLIC_DIR}/mix2 retval=$retval"