#!/bin/bash

source $(dirname "$0")/functions.sh

WORKSPACE_DIR=$1

if [ -z "${WORKSPACE_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

rave_print "Tallying encrypted ballots..."

CLASSPATH="build/libs/egk-rave-all.jar"

java -classpath $CLASSPATH \
  electionguard.cli.RunAccumulateTally \
    -in ${WORKSPACE_DIR}/eg \
    -eballots ${WORKSPACE_DIR}/bb/encryptedBallots \
    -out ${WORKSPACE_DIR}/eg

rave_print "[DONE] Tallying encrypted ballots."
