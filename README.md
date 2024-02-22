# Egk Mixnet

_last update 02.22.2024_

(Work in Progress)

Explorations of mixnet implementations to be used with the ElectionGuard Kotlin library. 

An optional interface to the GMP library has been added using Java 21 FFM. Using this library speeds up the overall workflow by 4-7x.
For details, see [egk mixnet maths](docs/mixnet_maths.pdf) To use this you need Java 21 to compile and run.

## Download

````
cd <install-dir>
git clone https://github.com/JohnLCaron/egk-mixnet.git
cd egk-mixnet
````

## Build

Prerequisites: Java 21

To build the code:

````
./gradlew clean assemble
./gradlew fatJar
````

If the library has changed and you need to update it:

````
cd ~/dev/github/egk-mixnet:
git fetch origin
git rebase -i origin/main
````

Then rebuild the code:

````
./gradlew clean assemble
./gradlew fatJar
````

## Build the C library using GMP (optional)

Install GMP on your machine into /usr/local/lib. You may use also use one of the other standard library directories, 
eg /usr/lib, but you may have to modify dev/github/egk-mixnet/src/main/c/Makefile.

Then build the interface to GMP:

````
cd ~/dev/github/egk-mixnet/src/main/c/:
make
sudo cp libegkgmp.so /usr/local/lib
````

The egk-mixnet library assumes that the library is in _/usr/local/lib/libegkgmp.so_.
You can modify _src/main/java/org/cryptobiotic/gmp/RuntimeHelper.java_ and rebuild if needed.

## Sample Workflow for testing

````
~/dev/github/egk-mixnet:$ ./scripts/completeWorkflow.sh working
````

Runs a complete test of the workflow and writes the output to whatever you set working to.
Note that you should erase that directory before running.

The components of this workflow are:

###  election-initialize.sh

. Uses _src/test/data/mixnetInput/manifest.json_ for the electionguard manifest. (Change in election-initialize.sh if you want)
. Creates an electiongurad configuration file with default election parameters. (Change in election-initialize.sh if you want)
. Runs the electionguard keyceremony to create private electionguard directory.
. Copies the public electionguard files to the public mixnet directory.

###  generate-and-encrypt-ballots.sh

1. Generates random plaintext ballots from the given manifest, writes to the private electionguard directory.
2. Encrypts those ballots with the public key, writes to the public mixnet directory.

###  mixnet-shuffle.sh

1. Shuffles the ballots using two shuffling phases, writes to the public mixnet directory.

###  mixnet-verify.sh

1. Runs the verifier on the mixnet proofs.

###  tally-ballots.sh 

1. Homomorphically accumulates encrypted ballots into an encrypted tally.

###  tally-decrypt.sh working

1. Uses trustee keys to decrypt the tally.

## Public directory file layout (strawman)

```
working/public
  encryptedBallots/
    eballot-id1.json
    eballot-id2.json
    ...
  mix1/
    Proof.json
    Shuffled.bin
  mix2/
    Proof.json
    Shuffled.bin
  ...
  mixN/
  
  constants.json
  election_config.json
  election_initialized.json
  encrypted_tally.json
  manifest.json
  tally.json
```

## Authors
- [John Caron](https://github.com/JohnLCaron)