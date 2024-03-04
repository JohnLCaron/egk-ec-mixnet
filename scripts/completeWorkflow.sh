# ~/.bashrc
WORKING=$1

if [ -z "${WORKING}" ]; then
    echo "No workspace provided."
    exit 1
fi

./scripts/election-initialize.sh ${WORKING}/private src/test/data/mixnetInput ${WORKING}/public
./scripts/generate-and-encrypt-ballots.sh ${WORKING}/private 10 ${WORKING}/public
./scripts/mixnet-shuffle.sh ${WORKING}/public
./scripts/mixnet-verify.sh ${WORKING}/public
# optional
./scripts/tally-ballots.sh ${WORKING}/public
./scripts/tally-decrypt.sh ${WORKING}/public ${WORKING}/private
./scripts/verify-eg.sh ${WORKING}/public

