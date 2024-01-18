# Egk Mixnet

_last update 11/18/2024_

(Work in Progress)

Preliminary explorations of mixnet implementations to be used with the ElectionGuard Kotlin library. 
Besides being a port to modern Kotlin, the code has been made parallel using kotlin coroutines.
Preliminary measurements show a 3x - 8x speedup vs verificatum.

Some of the code in org.cryptobiotic.mixnet.vmn is a port of code from the Verificatum repository
(https://github.com/verificatum/verificatum-vmn). Our library can independently verify mixnet output from Verificatum,
although we currently use the Verificatum library to calculate the generators, the e nonces, and the challenge.

Some of the code in org.cryptobiotic.mixnet.ch is a port of code from the OpenCHVote repository
(https://gitlab.com/openchvote/cryptographic-protocol).

Please use any of this work in any way consistent with those copyrights and licenses.

For details, see [egk mixnet maths](docs/mixnet_maths.pdf)

## Authors
- [John Caron](https://github.com/JohnLCaron)