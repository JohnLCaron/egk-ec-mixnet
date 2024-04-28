#!/bin/bash

PUBLIC_DIR=$1
PRIVATE_DIR=$2

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No public workspace provided."
    exit 1
fi

if [ -z "${PRIVATE_DIR}" ]; then
    echo "No private workspace provided."
    exit 1
fi

echo ""
echo "***mixnet-table, generate decrypted_sns.json"

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.cli.RunMixnetTable \
    -publicDir ${PUBLIC_DIR} \
    -trustees ${PRIVATE_DIR}/trustees \
    --mixDir ${PUBLIC_DIR}/mix2

retval=$?

echo " [DONE] Generating decrypted_sns.json retval=$retval"
