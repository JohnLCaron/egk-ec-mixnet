# ~/.bashrc
./scripts/election-initialize.sh working src/test/data/mixnetInput
./scripts/generate-and-encrypt-ballots.sh working 100
./scripts/mixnet-shuffle.sh working
./scripts/mixnet-verify.sh working
