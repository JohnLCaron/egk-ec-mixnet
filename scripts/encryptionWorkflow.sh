# ~/.bashrc
WORKING=$1

if [ -z "${WORKING}" ]; then
    echo "No workspace provided."
    exit 1
fi

# electionguard
./scripts/election-initialize.sh ${WORKING}/private src/test/data/mixnetInput ${WORKING}/public
./scripts/generate-and-encrypt-ballots.sh ${WORKING}/private 100 ${WORKING}/public