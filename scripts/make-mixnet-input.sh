#!/bin/bash

WORKSPACE_DIR=$1

if [ -z "${WORKSPACE_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

rave_print "***make-mixnet-input from the encrypted ballots"

MIXNET_WORKSPACE=${WORKSPACE_DIR}/vf
rm -rf ${VERIFICATUM_WORKSPACE}/*
mkdir -p ${VERIFICATUM_WORKSPACE}
mkdir -p ${WORKSPACE_DIR}/vf

CLASSPATH="build/libs/egkmixnet-0.8-SNAPSHOT-all.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.verificabitur.vmn.RunMakeMixnetInput \
    -eballots ${WORKSPACE_DIR}/bb/encryptedBallots \
    -out ${WORKSPACE_DIR}/vf/inputCiphertexts.bt

rave_print " [DONE] Creating mixnet input."
