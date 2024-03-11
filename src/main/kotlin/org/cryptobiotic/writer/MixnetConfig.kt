package org.cryptobiotic.writer

import kotlinx.serialization.Serializable

@Serializable
data class MixnetConfig(
    val width: Int,
)
