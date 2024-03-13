#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No public workspace provided."
    exit 1
fi

echo ""
echo "***mixnet-tally, compare to electionguard tally..."

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunMixnetTally \
    -publicDir ${PUBLIC_DIR} \
    --mixDir ${PUBLIC_DIR}/mix1

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunMixnetTally \
    -publicDir ${PUBLIC_DIR} \
    --mixDir ${PUBLIC_DIR}/mix2

echo " [DONE] Tallying mix1 and mix2 "
