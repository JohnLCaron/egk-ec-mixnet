#!/bin/bash

PRIVATE_DIR=$1
MANIFEST_DIR=$2
PUBLIC_DIR=$3

if [ -z "${PRIVATE_DIR}" ]; then
    echo "No private workspace provided."
    exit 1
fi

if [ -z "${MANIFEST_DIR}" ]; then
    echo "No manifest directory provided."
    exit 1
fi

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No public workspace provided."
    exit 1
fi

echo ""
echo "***initialize election into ${PRIVATE_DIR} directory"

mkdir -p ${PRIVATE_DIR}

cp  ${MANIFEST_DIR}/manifest.json ${PRIVATE_DIR}/

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

echo "   create election configuration"

java -classpath $CLASSPATH org.cryptobiotic.eg.cli.RunCreateElectionConfig \
    -manifest ${PRIVATE_DIR}/manifest.json \
    -group P-256 \
    -nguardians 3 \
    -quorum 3 \
    -out ${PRIVATE_DIR}

retval=$?

echo "   run CreateElectionConfig to generate configuration returns $retval"

java -classpath $CLASSPATH org.cryptobiotic.eg.cli.RunTrustedKeyCeremony \
    -in ${PRIVATE_DIR} \
    -trustees ${PRIVATE_DIR}/trustees \
    -out ${PRIVATE_DIR}

retval=$?

echo "   run TrustedKeyCeremony to generate the election keypair returns $retval"

echo "   copy electionguard files to public workspace ${PUBLIC_DIR}"

mkdir -p  ${PUBLIC_DIR}

cp ${PRIVATE_DIR}/constants.json ${PUBLIC_DIR}
cp ${PRIVATE_DIR}/election_config.json ${PUBLIC_DIR}
cp ${PRIVATE_DIR}/election_initialized.json ${PUBLIC_DIR}
cp ${PRIVATE_DIR}/manifest.json ${PUBLIC_DIR}

echo "   [DONE] initialize election into private ${PRIVATE_DIR} and public ${PUBLIC_DIR} directories"
