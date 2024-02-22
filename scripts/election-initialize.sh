#!/bin/bash

PRIVATE_DIR=$1
MANIFEST_DIR=$2
PUBLIC_DIR=$3

if [ -z "${PRIVATE_DIR}" ]; then
    rave_print "No private workspace provided."
    exit 1
fi

if [ -z "${MANIFEST_DIR}" ]; then
    rave_print "No manifest directory provided."
    exit 1
fi

if [ -z "${PUBLIC_DIR}" ]; then
    rave_print "No public workspace provided."
    exit 1
fi

echo ""
echo "***initialize election into ${PRIVATE_DIR} directory"

mkdir -p ${PRIVATE_DIR}

cp  ${MANIFEST_DIR}/manifest.json ${PRIVATE_DIR}/

CLASSPATH="build/libs/egkmixnet-0.84-SNAPSHOT-all.jar"

echo "   create election configuration"

 java -classpath $CLASSPATH electionguard.cli.RunCreateElectionConfig \
    -manifest ${PRIVATE_DIR}/manifest.json \
    -nguardians 3 \
    -quorum 3 \
    -out ${PRIVATE_DIR} \
    --baux0 device42

echo "   run KeyCeremony to generate the election keypair"

java -classpath $CLASSPATH electionguard.cli.RunTrustedKeyCeremony \
    -in ${PRIVATE_DIR} \
    -trustees ${PRIVATE_DIR}/trustees \
    -out ${PRIVATE_DIR}

echo "   copy electionguard files to public workspace ${PUBLIC_DIR}"

mkdir -p  ${PUBLIC_DIR}

cp ${PRIVATE_DIR}/constants.json ${PUBLIC_DIR}
cp ${PRIVATE_DIR}/election_config.json ${PUBLIC_DIR}
cp ${PRIVATE_DIR}/election_initialized.json ${PUBLIC_DIR}
cp ${PRIVATE_DIR}/manifest.json ${PUBLIC_DIR}

echo "   [DONE] initialize election into private ${PRIVATE_DIR} and public ${PUBLIC_DIR} directories"
