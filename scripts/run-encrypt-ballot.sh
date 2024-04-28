#!/bin/bash

INPUT_DIR="src/test/data/working/public"
PLAINTEXT_BALLOT="src/test/data/working/private/input_ballots/pballot-ballot11.json"
OUTPUT_DIR="src/test/data/testOut/egkmixnet/RunEncryptBallot"


if [ -z "${INPUT_DIR}" ]; then
    echo "No input directory provided."
    exit 1
fi

if [ -z "${PLAINTEXT_BALLOT}" ]; then
    echo "No ballot filename provided."
    exit 1
fi

if [ -z "${OUTPUT_DIR}" ]; then
    echo "No output directory provided."
    exit 1
fi

mkdir -p  ${OUTPUT_DIR}

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

echo "   RunEncryptBallot for ${PLAINTEXT_BALLOT}"

/usr/bin/java -classpath $CLASSPATH \
  org.cryptobiotic.eg.cli.RunEncryptBallot \
    --inputDir ${INPUT_DIR} \
    --ballotFilepath ${PLAINTEXT_BALLOT} \
    --outputDir ${OUTPUT_DIR} \
    -device device42 \
    --noDeviceNameInDir

retval=$?

echo "   [DONE] RunEncryptBallot return value $retval"
