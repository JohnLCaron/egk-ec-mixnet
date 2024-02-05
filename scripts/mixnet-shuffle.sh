#!/bin/bash

source $(dirname "$0")/functions.sh

WORKSPACE_DIR=$1

if [ -z "${WORKSPACE_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

rave_print "***mixnet shuffle encrypted ballots..."

VERIFICATUM_WORKSPACE="${WORKSPACE_DIR}/vf"

CLASSPATH="build/libs/egkmixnet-0.7-SNAPSHOT-all.jar"

# shuffle once
rave_print "  now shuffling ..."

java -classpath $CLASSPATH \
  org.cryptobiotic.verificabitur.vmn.RunVmnMixnetThreads \
    -vvvf ${VERIFICATUM_WORKSPACE} \
    -threads 1,2,4,6,8,12,16,20,24,28,32,36,40,44,48

rave_print " [DONE] Shuffling encrypted ballots"