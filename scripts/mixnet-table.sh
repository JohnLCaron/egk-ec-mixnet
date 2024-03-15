#!/bin/bash

PUBLIC_DIR=$1

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No public workspace provided."
    exit 1
fi

echo ""
echo "***mixnet-table, generate 'Digital Path' tables"

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunMixnetTable \
    -publicDir ${PUBLIC_DIR} \
    --mixDir ${PUBLIC_DIR}/mix2

echo " [DONE] Generating DigitalPath.csv, decrypted_sns.json "
