#!/bin/bash

source $(dirname "$0")/functions.sh

WORKSPACE_DIR=$1
VERIFICATUM_WORKSPACE=${WORKSPACE_DIR}/vf
rm -rf ${VERIFICATUM_WORKSPACE}/*
mkdir -p ${VERIFICATUM_WORKSPACE}
mkdir -p ${WORKSPACE_DIR}/vf

if [ -z "${WORKSPACE_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

rave_print "***make-mixnet-input from the encrypted ballots"

CLASSPATH="build/libs/egkmixnet-0.7-SNAPSHOT-all.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.verificabitur.vmn.RunMakeMixnetInput \
    -eballots ${WORKSPACE_DIR}/bb/encryptedBallots \
    -out ${WORKSPACE_DIR}/vf/inputCiphertexts.bt

rave_print " [DONE] Creating mixnet input."
