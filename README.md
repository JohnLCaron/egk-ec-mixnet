# Egk Mixnet Elliptic Curves

_last update 02.26.2024_

(Work in Progress)

Explorations of mixnet implementations to be used with the ElectionGuard Kotlin library. 

This version uses the [Egk Elliptic Curves library](https://github.com/JohnLCaron/egk-ec), 
and the [Verificatum library](https://www.verificatum.org/,
including the option to use the Verificatum C library. 

Note that the EC implementation is not stable and will change in the future. However, other than
different build instructions, this should not affect the API.

## Download

````
cd <install-dir>
git clone https://github.com/JohnLCaron/egk-ec-mixnet.git
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
cd ~/dev/github/egk-ec-mixnet:
git fetch origin
git rebase -i origin/main
````

Then rebuild the code:

````
./gradlew clean assemble
./gradlew fatJar
````

## Build the Verificatum C library using GMP (optional)

Follow the instructions in [Egk-ec Getting Started)(https://github.com/JohnLCaron/egk-ec/blob/main/docs/GettingStarted.md#using-the-verificatum-library-optional)

## Sample Workflow for testing

````
~/dev/github/egk-ec-mixnet:$ ./scripts/completeWorkflow.sh working
````

Runs a complete test of the workflow and writes the output to whatever you set _working_ to.

The components of this workflow are:

###  election-initialize.sh

* Uses _src/test/data/mixnetInput/manifest.json_ for the egk manifest. (Change in election-initialize.sh if you want)
* Creates an egk configuration file with default election parameters. (Change in election-initialize.sh if you want)
* Runs the egk keyceremony to create private egk directory.
* Copies the public egk files to the public mixnet directory.

###  generate-and-encrypt-ballots.sh

* Generates random plaintext ballots from the given manifest, writes to the private egk directory.
* Encrypts those ballots with the public key, writes to the public mixnet directory.

###  mixnet-shuffle.sh

* Shuffles the ballots using two shuffling phases, writes to the public mixnet directory.

###  mixnet-verify.sh

*  Runs the verifier on the mixnet proofs.

###  tally-ballots.sh 
* Homomorphically accumulates encrypted ballots into an encrypted tally.

###  tally-decrypt.sh working

* Uses trustee keys to decrypt the tally.

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