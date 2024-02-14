#!/bin/bash

WORKSPACE_DIR=$1

if [ -z "${WORKSPACE_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

rave_print "***mixnet-initialize verificatum..."

EG_WORKSPACE="${WORKSPACE_DIR}/eg"
VERIFICATUM_WORKSPACE="${WORKSPACE_DIR}/vf"

CLASSPATH="build/libs/egkmixnet-0.8-SNAPSHOT-all.jar"
java -classpath $CLASSPATH \
  org.cryptobiotic.verificabitur.vmn.RunMixnetConfig \
    -input ${EG_WORKSPACE} \
    -working ${VERIFICATUM_WORKSPACE}

rave_print " [DONE] Initialize verificatum mixnet in directory ${VERIFICATUM_WORKSPACE}"
