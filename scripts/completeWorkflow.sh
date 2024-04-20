# ~/.bashrc
WORKING=$1

if [ -z "${WORKING}" ]; then
    echo "No workspace provided."
    exit 1
fi

# electionguard
./scripts/election-initialize.sh ${WORKING}/private src/test/data/mixnetInput ${WORKING}/public
./scripts/generate-and-encrypt-ballots.sh ${WORKING}/private 100 ${WORKING}/public
./scripts/eg-tally.sh ${WORKING}/public
./scripts/eg-tally-decrypt.sh ${WORKING}/public ${WORKING}/private
./scripts/eg-verify.sh ${WORKING}/public

# mixnet
./scripts/mixnet-shuffle.sh ${WORKING}/public
./scripts/mixnet-verify.sh ${WORKING}/public

# cacvote
./scripts/table-mixnet.sh ${WORKING}/public ${WORKING}/private
./scripts/table-pballot.sh ${WORKING}/public ${WORKING}/private
./scripts/pballot-decrypt.sh ${WORKING}/public ${WORKING}/private
./scripts/verify-decryptions.sh ${WORKING}/public ${WORKING}/private