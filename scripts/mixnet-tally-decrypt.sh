#!/bin/bash

PUBLIC_DIR=$1
PRIVATE_DIR=$2

if [ -z "${PUBLIC_DIR}" ]; then
    echo "No public workspace provided."
    exit 1
fi

if [ -z "${PRIVATE_DIR}" ]; then
    echo "No private workspace provided."
    exit 1
fi

echo ""
echo "*** mixnet tally decrypt..."

CLASSPATH="build/libs/egk-ec-mixnet-2.1-SNAPSHOT-uber.jar"

java -classpath $CLASSPATH \
  org.cryptobiotic.eg.cli.RunTrustedTallyDecryption \
    -in ${PUBLIC_DIR} \
    -trustees ${PRIVATE_DIR}/trustees \
    --encryptedTallyFile ${PUBLIC_DIR}/mix1/encrypted_tally.json \
    -out ${PUBLIC_DIR}/mix1

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunCompareTally \
    -publicDir ${PUBLIC_DIR} \
    --mixDir ${PUBLIC_DIR}/mix1 \
    -show

echo "   [DONE] Decrypted mixnet tally into ${PUBLIC_DIR}/mix1/tally.json"

java -classpath $CLASSPATH \
  org.cryptobiotic.eg.cli.RunTrustedTallyDecryption \
    -in ${PUBLIC_DIR} \
    -trustees ${PRIVATE_DIR}/trustees \
    --encryptedTallyFile ${PUBLIC_DIR}/mix2/encrypted_tally.json \
    -out ${PUBLIC_DIR}/mix2

java -classpath $CLASSPATH \
  org.cryptobiotic.mixnet.RunCompareTally \
    -publicDir ${PUBLIC_DIR} \
    --mixDir ${PUBLIC_DIR}/mix2 \
    -show

echo "   [DONE] Decrypted mixnet tally into ${PUBLIC_DIR}/mix2/tally.json"
