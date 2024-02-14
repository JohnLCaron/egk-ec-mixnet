# Egk Mixnet

_last update 02.14.2024_

(Work in Progress)

Explorations of mixnet implementations to be used with the ElectionGuard Kotlin library. 
Besides being a port to modern Kotlin, the mixnet has been made parallel using Kotlin coroutines.
Preliminary measurements show significant speedup vs Verificatum. For details, see [egk mixnet maths](docs/mixnet_maths.pdf)

An optional interface to the GMP library has been added using Java 21 FFM. This means you need java 21 to compile and 
run. If you remove that, you can use Java 17. 

An early draft of a mixnet workflow script can be found in scripts/completeWorkflow.sh.

## Authors
- [John Caron](https://github.com/JohnLCaron)