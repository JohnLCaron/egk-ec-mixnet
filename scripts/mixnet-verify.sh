#!/bin/bash

source $(dirname "$0")/functions.sh

WORKSPACE_DIR=$1

if [ -z "${WORKSPACE_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

rave_print "***mixnet-verify..."

EG_BB="${WORKSPACE_DIR}/bb/eg"
VF_BB="${WORKSPACE_DIR}/bb/vf"

CLASSPATH="build/libs/egkmixnet-0.7-SNAPSHOT-all.jar"

rave_print "  ... verify mix1 shuffle ..."

java -classpath $CLASSPATH \
  org.cryptobiotic.verificabitur.vmn.RunVmnVerifierThreads \
    --vvbb ${VF_BB} \
    -threads 1,2,4,6,8,12,16,20,24,28,32,36,40,44,48


rave_print " [DONE] Verifying shuffled ballots"
