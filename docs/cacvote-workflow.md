# EGK-Mixnet Cacvote Workflow Notes
4/23/24

<!-- TOC -->
* [EGK-Mixnet Cacvote Workflow Notes](#egk-mixnet-cacvote-workflow-notes)
  * [Config](#config)
  * [Encrypt](#encrypt)
  * [Sign](#sign)
  * [Mix](#mix)
  * [Compare](#compare)
  * [RLA](#rla)
  * [Other Auditing needs (TBD)](#other-auditing-needs-tbd)
<!-- TOC -->

## Config

Before the election, for each jurisdiction:

1.1 An "election manifest" is made capturing the ballot styles, contests and selections. (Note that the term "manifest" is also used to mean the record of who voted, I think. Do we need to change terminology to reduce confusion?)

1.2 The _election-initialize.sh_ script is run which configures the election and writes the trustee keys into a private directory. The constants.json, election_config.json, election_initialized.json, and manifest.json files are written to the public directory. 

1.3 The public files must be distributed to each of the encryption devices in the field. (With signatures or checksums for tamper-resistance?). The private keys must not be distributed. 


## Encrypt

During the election, for each encryption device:

2.1 For each ballot to be cast, the "plaintext ballot" must be written to the correct format, then sent to RunEncryptBallot, which writes its encryption to a specified directory. For each ballot, the jurisdiction is indicated to RunEncryptBallot by pointing to the correct public directory.

2.2 If ballot chaining is used, a "ballot_chain.json" file is read and written for each ballot, specific to each jurisdiction and ballot chain (usually each device). This file must remain persistant for the duration of the election. (If this is a problem, I have some other things we can do that push the complexity to the post-processing). For cacvote, we will not use ballot chaining.

2.3 We need to prototype error handling and diagnostics for this phase, eg ballot/manifest mismatch. This is always a configuration error, so we should be able to test for and eliminate any possibility of it happening during an election (gulp).


## Sign

After the election, for each encryption device:

3.1 The signed, encrypted ballots are safely transported to the appropriate jurisdiction server (or public BB).

3.2 All ballots for all styles and devices can be placed into a single place for further processing. If/when we do ballot chaining, there may be some extra tasks here.

3.3 Process/validate the digital signatures.


## Mix

After the election, for each jurisdiction:

4.1 Run the electionguard tally, decrypt tally, and electionguard verification on the election record, 
and place the results in the public directory. (_eg-tally.sh, eg-tally-decrypt.sh, and eg-verify.sh_)

4.2 Run the mixnet (_mixnet-shuffle.sh_) on all CAST ballots. (For cacvote, these are always CAST, there are no CHALLENGE's). 
For the prototype, each mix is done by the system. Currently we are doing 2 mixes. 
Publish the mixnet results (shuffled ballots and proofs) to the BB. (**change paper to indicate all cast ballots are mixed)

4.2.1 Mix all ballots for a given jurisdictiion/election, regardless of ballot type.

The way we do that is to count the number of selections for each ballot type that we have a ballot for. 
Then take the maximum, and use that as the width of each row (row == ballot). 
The mixnet requires uniform width of all rows. 
So for ballot types with nselections < width, we just fill the row with random encryptions of 0. 
We also encrypt the ballot style index in each row, which is then available when decrypting, and use it to read only
the actual number of selections, and assign them to the correct contests.

The downside is we cannot do homomorphic tallying of the shuffled ballots. 
But we weren't doing that anyway (we only do it on the electionguard encrypted ballots).

The upside is that theres a single set of mixnet files for each jurisdiction and mix stage. 
Simpler in terms of number of files to keep track of. Arguably a bit less privacy revealing when nballots is small.

VT Comments: 
* Mix the whole jurisdiction's ballots (for privacy). This is definitely right in some jurisdictions (eg CO) that sample 
from the whole set. In others, it's advantageous to know the ballot type for sampling. Either mix per ballot style or 
(equivalently) add a field to the data that states ballot type; mix in; perhaps it's not always necessary to completely decrypt.

JC Comments: 
* The ballot style is in the decrypted_sns.json. So ballots could be sampled within their ballot style if needed,
without decrypting the entire ballot.

4.3 Run _mixnet-verify.sh_ to verify the mixes.

4.4 Run _table-mixnet.sh_ to generate a table consisting of, for each ballot, the decrypted K^sn, and its row index in the final shuffled-ballots file.
These decrypted K^sn and their proofs are public in _decrypted_sns.json_ (aka "Digital Path table")

##  Compare

After the election, for each jurisdiction:

5.1 As the paper ballots are received, maintain a table consisting of, for each ballot, the paper ballot serial number (psn) 
and a pointer to the physical location of the ballot. These are in _pballot-table.json_ (aka "Paper Path table").

5.1.1 The _table-pballot.sh_ script simulates this step for testing purposes.

5.2 At any point, run make-tables.sh (TODO) that reads the Digital Path table and the Paper Path table, and constructs any of the tables D2, D2', D3, D4, D5. 
Check that there are no duplicate psn. Produce any statistics needed for the RLA.

VT Comments: 
* If we're mixing everything then the 'non-arrived' stack (D2') will disappear and all those ballots will end up in the 'non-matching' stack.

JC Comments:
* We need the "non-matching set" for 7.2. Clarify if any of the other D tables need to be instantiated, or if they are logical constructs for the paper. 


## RLA

After the election, for each jurisdiction:

6.1 Given a serial number, use _pballot_decrypt.sh to produce the corresponding Simplified Ballot from the final mixnet, and its decryption. 
A Simplified Ballot consists of just the ballot's contest and selection names and their encrypted vote. 
Its decryption decrypts the votes to plaintext, and provides proof of correct decryption. The decrypted ballot(s) are placed into 
private/decrypted_ballots.

6.1.1 Its possible this decryption is done by contest, in which case the serial number and contest name is given, 
and the output is restricted to that contest.

6.1.2 The _pballot_decrypt.sh_ script also accepts "random" or "all" instead of a psn, for testing purposes.

6.2 The _verify_decryptions.sh_ script is used to verify the proofs of the decryptions

6.2.1 The _verify_decryptions.sh_ script always reads _decrypted_sns.json_ and verifies the proofs there.

6.2.2 If the _--decryptedBallotDir_ command line argument is given to _verify_decryptions.sh_, then all the ballots in the 
decrypted ballot directory are read and their proofs are validated.

6.2.3 If the _--originalBallotDir_ command line argument is given to _verify_decryptions.sh_ (as well as _--decryptedBallotDir_), 
then all the ballots in the decrypted ballot directory are read, as well as the _pballot-table.json_ table. When there 
is a match between the two, the decrypted ballot is compared to the original paper ballot, and any discrepencies are printed out.

## Other Auditing needs (TBD)

7.1 Auditors need to match the serial numbers and compute the discrepancies for the ballot.

7.2 We may need a program _tally_ballot_list.sh_ (TODO), where a list of psn are given, those ballots are found and tallied, 
and the output is its decrypted tally. This only needs to happen for those ballots in the non-matching set.

7.3 The auditors are going to need a little app that does some verifications - see "Verification at the local counting center", 
which perhaps could clarify which things are for the auditors and which are for the local officials. 

