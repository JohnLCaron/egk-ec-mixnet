#!/bin/bash

WORKSPACE_DIR=$1
MANIFEST_DIR=$2

if [ -z "${WORKSPACE_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

if [ -z "${MANIFEST_DIR}" ]; then
    rave_print "No manifest directory provided."
    exit 1
fi

echo "***initialize election: ${WORKSPACE_DIR} directory"

rm -rf ${WORKSPACE_DIR}/*

mkdir -p  ${WORKSPACE_DIR}/eg

cp  ${MANIFEST_DIR}/manifest.json ${WORKSPACE_DIR}/eg/

CLASSPATH="build/libs/egkmixnet-0.8-SNAPSHOT-all.jar"

echo "   create election configuration"

 java -classpath $CLASSPATH electionguard.cli.RunCreateElectionConfig \
    -manifest ${WORKSPACE_DIR}/eg/manifest.json \
    -nguardians 3 \
    -quorum 3 \
    -out ${WORKSPACE_DIR}/eg \
    --baux0 device42

echo "   run KeyCeremony to generate the election keypair"

java -classpath $CLASSPATH electionguard.cli.RunTrustedKeyCeremony \
    -in ${WORKSPACE_DIR}/eg \
    -trustees ${WORKSPACE_DIR}/eg/trustees \
    -out ${WORKSPACE_DIR}/eg

echo "   [DONE] initialize election into ${WORKSPACE_DIR}/eg/"
