#!/bin/bash

PRIVATE_DIR=$1
NUM_BALLOTS=$2
PUBLIC_DIR=$3

if [ -z "${PRIVATE_DIR}" ]; then
    rave_print "No private workspace provided."
    exit 1
fi

if [ -z "${NUM_BALLOTS}" ]; then
    rave_print "No number of ballots provided."
    exit 1
fi

if [ -z "${PUBLIC_DIR}" ]; then
    rave_print "No public workspace provided."
    exit 1
fi

echo ""
echo "***generate and encrypt ballots:"

mkdir -p  ${PRIVATE_DIR}/inputBallots
mkdir -p  ${PUBLIC_DIR}/encryptedBallots

CLASSPATH="build/libs/egkmixnet-0.8-SNAPSHOT-all.jar"

echo "   Create ${NUM_BALLOTS} test ballots..."

java -classpath $CLASSPATH \
     electionguard.cli.RunCreateInputBallots \
       -manifest ${PRIVATE_DIR}/manifest.json \
       -out ${PRIVATE_DIR}/inputBallots \
       --nballots ${NUM_BALLOTS} \
       -json

echo "   Encrypting ${NUM_BALLOTS} ballots..."

java -classpath $CLASSPATH \
  electionguard.cli.RunBatchEncryption \
    -in ${PRIVATE_DIR} \
    -ballots ${PRIVATE_DIR}/inputBallots \
    -eballots ${PUBLIC_DIR}/encryptedBallots \
    -device device42

echo "   [DONE] Generating encrypted ballots into ${PUBLIC_DIR}/encryptedBallots/"
