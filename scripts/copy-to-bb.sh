#!/bin/bash

source $(dirname "$0")/functions.sh

WORKSPACE_DIR=$1

if [ -z "${WORKSPACE_DIR}" ]; then
    rave_print "No workspace provided."
    exit 1
fi

rave_print "***copy to bb"

EG_WORKSPACE="${WORKSPACE_DIR}/eg"
VF_WORKSPACE="${WORKSPACE_DIR}/vf"
BULLETIN_BOARD="${WORKSPACE_DIR}/bb"

mkdir -p ${BULLETIN_BOARD}/eg
cp ${EG_WORKSPACE}/* ${BULLETIN_BOARD}/eg

mkdir -p ${BULLETIN_BOARD}/vf
cp ${VF_WORKSPACE}/protocolInfo.xml ${BULLETIN_BOARD}/vf
cp ${VF_WORKSPACE}/publicKey.bt ${BULLETIN_BOARD}/vf
# cp ${VF_WORKSPACE}/inputCiphertexts.bt ${BULLETIN_BOARD}/vf

mkdir -p ${BULLETIN_BOARD}/vf/mix1
cp ${VF_WORKSPACE}/inputCiphertexts.bt ${BULLETIN_BOARD}/vf/mix1/Ciphertexts.bt
cp ${VF_WORKSPACE}/Party01/nizkp/mix1/ShuffledCiphertexts.bt ${BULLETIN_BOARD}/vf/mix1/
cp ${VF_WORKSPACE}/Party01/nizkp/mix1/FullPublicKey.bt ${BULLETIN_BOARD}/vf/mix1/
mkdir -p ${BULLETIN_BOARD}/vf/mix1/proofs
cp ${VF_WORKSPACE}/Party01/nizkp/mix1/proofs/PoSReply01.bt ${BULLETIN_BOARD}/vf/mix1/proofs/
cp ${VF_WORKSPACE}/Party01/nizkp/mix1/proofs/PoSCommitment01.bt ${BULLETIN_BOARD}/vf/mix1/proofs/
cp ${VF_WORKSPACE}/Party01/nizkp/mix1/proofs/PermutationCommitment01.bt ${BULLETIN_BOARD}/vf/mix1/proofs/

rave_print " [DONE] Copying files to public Bulletin Board"
