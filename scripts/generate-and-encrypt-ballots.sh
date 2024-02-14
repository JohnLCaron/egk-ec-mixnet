#!/bin/bash

WORKSPACE_DIR=$1
NUM_BALLOTS=$2

if [ -z "${WORKSPACE_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

if [ -z "${NUM_BALLOTS}" ]; then
    rave_print "No number of ballots provided."
    exit 1
fi


echo "***generate and encrypt ${NUM_BALLOTS} ballots:"

CLASSPATH="build/libs/egkmixnet-0.8-SNAPSHOT-all.jar"

java -classpath $CLASSPATH \
     electionguard.cli.RunCreateInputBallots \
       -manifest ${WORKSPACE_DIR}/eg/manifest.json \
       -out ${WORKSPACE_DIR}/eg/inputBallots \
       --nballots ${NUM_BALLOTS} \
       -json

echo "   Encrypting ${NUM_BALLOTS} ballots..."

java -classpath $CLASSPATH \
  electionguard.cli.RunBatchEncryption \
    -in ${WORKSPACE_DIR}/eg \
    -ballots ${WORKSPACE_DIR}/eg/inputBallots \
    -eballots ${WORKSPACE_DIR}/bb/encryptedBallots \
    -device device42

echo "   [DONE] Generating encrypted ballots into ${WORKSPACE_DIR}/bb/encryptedBallots/"
