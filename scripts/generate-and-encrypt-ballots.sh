#!/bin/bash

PRIVATE_DIR=$1
NUM_BALLOTS=$2
PUBLIC_DIR=$3

if [ -z "${PRIVATE_DIR}" ]; then
    echo "No private workspace provided."
    exit 1
fi

if [ -z "${NUM_BALLOTS}" ]; then
    echo "No number of ballots provided."
    exit 1
fi

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No public workspace provided."
    exit 1
fi

echo ""
echo "***generate and encrypt ballots:"

rm -rf ${PRIVATE_DIR}/inputBallots/*
rm -rf ${PUBLIC_DIR}/encrypted_ballots/*

mkdir -p  ${PRIVATE_DIR}/inputBallots
mkdir -p  ${PUBLIC_DIR}/encrypted_ballots

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

echo "   RunExampleEncryption for ${NUM_BALLOTS} ballots..."

/usr/bin/java -classpath $CLASSPATH \
  org.cryptobiotic.eg.cli.RunExampleEncryption \
    -config ${PRIVATE_DIR} \
    -nballots 11 \
    -pballotDir ${PRIVATE_DIR}/inputBallots \
    -eballotDir ${PUBLIC_DIR}/encrypted_ballots/device42 \
    -device device42

echo "   [DONE] Generating encrypted ballots into ${PUBLIC_DIR}/encrypted_ballots/device42"
