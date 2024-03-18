#!/bin/bash

PUBLIC_DIR=$1
PRIVATE_DIR=$2

if [ -z "${PRIVATE_DIR}" ]; then
    echo "No private workspace provided."
    exit 1
fi

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No public workspace provided."
    exit 1
fi

echo ""
echo "***table-pballot: make simulated paper ballot table"

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

/usr/bin/java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.cli.RunPballotTable \
    -publicDir ${PUBLIC_DIR} \
    -pballotDir ${PRIVATE_DIR}/input_ballots \
    --missingPct 10

echo "   [DONE] Generated simulated paper ballot table into ${PUBLIC_DIR}/table-pballot.json"
