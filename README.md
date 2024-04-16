[![License](https://img.shields.io/github/license/JohnLCaron/egk-ec)](https://github.com/JohnLCaron/egk-ec-mixnet/blob/main/LICENSE.txt)
![GitHub branch checks state](https://img.shields.io/github/actions/workflow/status/JohnLCaron/egk-ec-mixnet/unit-tests.yml)
![Coverage](https://img.shields.io/badge/coverage-88.7%25%20LOC%20(1345/1516)-blue)

# Egk Elliptic Curves Mixnet 

_last update 04/16/2024_

Implementation of a mixnet using the [ElectionGuard Kotlin Elliptical Curve library](https://github.com/JohnLCaron/egk-ec),
and the [Verificatum library](https://www.verificatum.org/). The mixnet uses the Terelius / Wikström (TW) mixnet
algorithm, see  [egk mixnet maths](docs/mixnet_maths.pdf) for details. Note that paper's timings use the older
integer group; the elliptic curve group is [much faster](docs/egk-ec-mixnet.png).

This is part of [VotingWork's cacvote project](https://github.com/votingworks/cacvote). It is not part of the ElectionGuard specification per se, but follows the
ElectionGuard 2.0 specification wherever possible.

The implementation for Elliptical Curves (EC) is derived from the [Verificatum library](https://www.verificatum.org/),
including the option to use the Verificatum C library. See [VCR License](LICENSE_VCR.txt) for the license for this part of
the library.

Note that the EC implementation is not stable and may change in the future. However, other than
different build instructions, this should not affect the API.

<!-- TOC -->
* [Egk Elliptic Curves Mixnet](#egk-elliptic-curves-mixnet-)
  * [Timing](#timing)
  * [Size](#size)
  * [Download](#download)
  * [Build](#build)
  * [Rebuild](#rebuild)
  * [Build the Verificatum C library using GMP (optional)](#build-the-verificatum-c-library-using-gmp-optional)
  * [Sample Workflow for testing](#sample-workflow-for-testing)
    * [electionguard](#electionguard)
      * [election-initialize.sh](#election-initializesh)
      * [generate-and-encrypt-ballots.sh](#generate-and-encrypt-ballotssh)
      * [eg-tally.sh](#eg-tallysh)
      * [eg-tally-decrypt.sh](#eg-tally-decryptsh)
      * [eg-verify.sh](#eg-verifysh)
    * [mixnet](#mixnet)
      * [mixnet-shuffle.sh](#mixnet-shufflesh)
      * [mixnet-verify.sh](#mixnet-verifysh)
    * [cacvote](#cacvote)
      * [table-mixnet.sh](#table-mixnetsh)
      * [table-pballot.sh](#table-pballotsh)
      * [pballot-decrypt](#pballot-decrypt)
      * [verify-decryptions](#verify-decryptions)
  * [Directory file layout (strawman)](#directory-file-layout-strawman)
  * [Authors](#authors)
<!-- TOC -->

## Timing

Encrypting a ballot with 12 contests and 4 selections each (total of 60 encryptions) takes about 6 ms per ballot,
using pre-computed tables for "fixed base acceleration". This does not appear to be using Montgomery forms for fast mod operation.

Mixing 1000 ballots of width 34 takes ~ 17 secs single threaded with good parallelization. 
Verification is 30-50% slower than the shuffle and proof, [see plot](docs/egk-ec-mixnet.png).

## Size

We use "point compression" on the elliptic curve ElementModP, so we only serialize the x and "sign of y" coordinates, 
giving a storage reduction of O(64/33) compared to serializing both coordinates, and O(512/33) compared to the integer group. 
To estimate the computational cost of storing just x and recomputing y: BallotReader reads
1000 ballots (width 34) in 235 msecs. If one computes y instead of reading it, it takes 1274 msecs.
So, cost is ~ 1 sec for 34000 texts everytime you have to read the mixed ballots.

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

## Rebuild

If the library has changed and you need to update it:

````
cd ~/dev/github/egk-ec-mixnet:
git fetch origin
git rebase origin/main
````

Then rebuild the code:

````
./gradlew clean assemble
./gradlew uberJar
````

## Build the Verificatum C library using GMP (optional)

Follow the instructions in [Egk-ec Getting Started](https://github.com/JohnLCaron/egk-ec/blob/main/docs/GettingStarted.md#using-the-verificatum-library-optional)

This is needed for good performance.

## Sample Workflow for testing

````
~/dev/github/egk-ec-mixnet:$ ./scripts/completeWorkflow.sh working
````

Runs a complete test of the workflow and writes the output to whatever you set _working_ to.

After running, examine the log file at **_egkMixnet.log_**.

The components of this workflow are:

### electionguard

####  election-initialize.sh

* Uses _src/test/data/mixnetInput/manifest.json_ for the egk manifest. (Change in election-initialize.sh if you want)
* Creates an egk configuration file with default election parameters. (Change in election-initialize.sh if you want)
* Runs the egk keyceremony to create private egk directory.
* Copies the public egk files to the public mixnet directory.

####  generate-and-encrypt-ballots.sh

* Generates random plaintext ballots from the given manifest, and writes their encryptions to the public mixnet directory.
* This is the main functionality that needs to be implemented by the election voting system. Likely the voting system will 
  write the plaintext ballot to disk and call RunEncryptBallot.main() with appropriate parameters. 

####  eg-tally.sh

* Homomorphically accumulates digital ballots into an encrypted tally.

####  eg-tally-decrypt.sh

* Uses trustee keys to decrypt the tally.

####  eg-verify.sh

* Runs the egk verifier to do electionguard verification.


### mixnet

####  mixnet-shuffle.sh

* Shuffles the ballots using two shuffling phases, writes to the public mixnet directory.

####  mixnet-verify.sh

*  Runs the verifier on the mixnet proofs.


### cacvote

####  table-mixnet.sh

* From the last mix's ShuffledBallots, generate table of decrypted (K^sn) serial numbers and proofs. 
* This table is written to _working/public/decrypted_sns.json_.

####  table-pballot.sh

* Simulate a table of paper ballot serial numbers and their physical locations.
* Pass in "--missingPct percent" to simulate some percent of paper ballots were not received.
* This table is written to _working/public/pballot_table.json_.

####  pballot-decrypt

* From a paper ballot's serial number (psn), find the corresponding shuffled ballot and decrypt it. 
* Place decrypted ballot into _private/decrypted_ballots/_ directory. 
* Use psn as the decrypted ballot id, and the filename is _dballlot-psn.json_.

####  verify-decryptions

* Verify the proofs in the decrypted serial numbers (decrypted_sns.json). 
* Verify the decrypted ballot proofs.
* If digital copies of the paper ballots are available, compare the ballot decryptions to the originals.


## Directory file layout (strawman)

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
    mix_config.json
    proof_of_shuffle.json
    ShuffledBallots.bin
  mix2/
    mix_config.json
    proof_of_shuffle.json
    ShuffledBallots.bin
  mixN/
    ...
  
  constants.json
  election_config.json
  election_initialized.json
  encrypted_tally.json
  manifest.json
  tally.json
  
  decrypted_sns.json
  pballot-table.json
  
working/private 
  input_ballots/ 
    pballot-id1.json
    pballot-id2.json
    ...
  trustees/
    decrypting_trustee-name1
    decrypting_trustee-name2
    ...
  decrypted_ballots/
    dballot-sn1.json
    dballot-sn2.json
    ...
```

## Authors
- [John Caron](https://github.com/JohnLCaron)