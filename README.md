# Egk Mixnet Elliptic Curves

_last update 04.04.2024_

(Work in Progress)

Explorations of mixnet implementations to be used with the ElectionGuard Kotlin library. 

This version uses the [Egk Elliptic Curves library](https://github.com/JohnLCaron/egk-ec), 
and the [Verificatum library](https://www.verificatum.org/, including the option to use the Verificatum C library

This is a prototype feature and is not part of the ElectionGuard specification.
The implementation for Elliptical Curves (EC) is taken largely from the [Verificatum library](https://www.verificatum.org/,
including the option to use the Verificatum C library. See [VCR License](LICENSE_VCR.txt) for the license for this part of
the library.

Note that the EC implementation is not stable and will change in the future. However, other than
different build instructions, this should not affect the API.

## Timing

Encrypting a ballot with 12 contests and 4 selections each (total of 60 encryptions) takes about 6 ms per ballot,
using pre-computed tables for "fixed base acceleration". This does not appear to be using Montgomery forms for fast mod operation.

Mixing 1000 ballots of width 34 takes ~ 17 secs single threaded with good parallelization. 
Verification is 30-50% slower, [see plot](docs/egk-ec-mixnet.png).

## Size

We use "point compression" on the elliptic curve ElmeentModP, so we only serialize the x and "sign of y" coordinates, 
giving a storage reduction of O(64/33) compared to serializing both coordinates, and O(512/33) compared to the integer group. 
To estimate the computational cost of storing just x and recomputing y: BallotReader reads
1000 ballots (width 34) in 235 msecs. If one computes y instead of reading it, it takes 1274 msecs.
So, cost is ~ 1 sec for 34000 texts everytime you have to read the mixed ballots. This reduces size to
O(512/33).

Currently we store the ballots in binary and the proofs in json in base64.
For very large mixnets, you might want to store proofs as efficiently as possible, which argues for a protobuf option.

````
readMixnetBallots from working/public/mix1/Shuffled.bin nrows = 1000 width=34
BallotReader took 2352 msecs = .006917 msecs/text (340000 texts) = 235.2 msecs/trial for 10 trials
BallotReaderAlt took 12744 msecs = .03748 msecs/text (340000 texts) = 1274 msecs/trial for 10 trials
````

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
./gradlew uberJar
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
./gradlew uberJar
````

## Build the Verificatum C library using GMP (optional)

Follow the instructions in [Egk-ec Getting Started)(https://github.com/JohnLCaron/egk-ec/blob/main/docs/GettingStarted.md#using-the-verificatum-library-optional)

This is needed for good performance.

## Sample Workflow for testing

````
~/dev/github/egk-ec-mixnet:$ ./scripts/completeWorkflow.sh working
````

Runs a complete test of the workflow and writes the output to whatever you set _working_ to.

After running, examine the log file at **_egkMixnet.log_**.

The components of this workflow are:

###  election-initialize.sh

* Uses _src/test/data/mixnetInput/manifest.json_ for the egk manifest. (Change in election-initialize.sh if you want)
* Creates an egk configuration file with default election parameters. (Change in election-initialize.sh if you want)
* Runs the egk keyceremony to create private egk directory.
* Copies the public egk files to the public mixnet directory.

###  generate-and-encrypt-ballots.sh

* Generates random plaintext ballots from the given manifest, and writes their encryptions to the public mixnet directory.
* This is the main functionality that needs to be implemented by the election voting system.

###  mixnet-shuffle.sh

* Shuffles the ballots using two shuffling phases, writes to the public mixnet directory.

###  mixnet-verify.sh

*  Runs the verifier on the mixnet proofs.

###  tally-ballots.sh 
* Homomorphically accumulates encrypted ballots into an encrypted tally.

###  tally-decrypt.sh working

* Uses trustee keys to decrypt the tally.

###  verify-eg.sh working

* Runs the egk verifier to do electionguard verification.


## Public directory file layout (strawman)

```
working/public
  encrypted_ballots/
    device1/
      eballot-id1.json
      eballot-id2.json
    device2/
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