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

rm -rf ${PRIVATE_DIR}/input_ballots/*
rm -rf ${PUBLIC_DIR}/encrypted_ballots/*

mkdir -p  ${PRIVATE_DIR}/input_ballots
mkdir -p  ${PUBLIC_DIR}/encrypted_ballots

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

echo "   RunExampleEncryption for ${NUM_BALLOTS} ballots, 2 devices but single directory"

/usr/bin/java -classpath $CLASSPATH \
  org.cryptobiotic.eg.cli.RunExampleEncryption \
    -config ${PRIVATE_DIR} \
    -nballots 21 \
    -pballotDir ${PRIVATE_DIR}/input_ballots \
    -eballotDir ${PUBLIC_DIR}/encrypted_ballots \
    -device device42,yerDevice

echo "   [DONE] Generating encrypted ballots into ${PUBLIC_DIR}/encrypted_ballots"
