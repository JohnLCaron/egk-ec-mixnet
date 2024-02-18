package org.cryptobiotic.vec

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap

// TODO make this settable. The maximum vote allowed for the tally.
private const val MAX_DLOG: Int = 100_000

class ECLog(val group: VecGroup) {
    val base = group.g

    private val dLogMapping: MutableMap<VecGroupElement, Int> =
        ConcurrentHashMap<VecGroupElement, Int>()
            .apply {
                this[group.ONE] = 0
            }

    private var dLogMaxElement = group.ONE
    private var dLogMaxExponent = 0

    private val mutex = Mutex()

    fun dLog(input: VecGroupElement, maxResult: Int): Int? =
        if (input in dLogMapping) {
            dLogMapping[input]
        } else {
            runBlocking {
                mutex.withLock {
                    // We need to check the map again; it might have changed.
                    if (input in dLogMapping) {
                        dLogMapping[input]
                    } else {
                        var error = false
                        val dlogMax = if (maxResult < 0) MAX_DLOG else maxResult

                        while (input != dLogMaxElement) {
                            if (dLogMaxExponent++ > dlogMax) {
                                error = true
                                break
                            } else {
                                dLogMaxElement = dLogMaxElement.mul(base)
                                dLogMapping[dLogMaxElement] = dLogMaxExponent
                            }
                        }

                        if (error) null else dLogMaxExponent
                    }
                }
            }
        }
}