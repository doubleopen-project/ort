/*
 * SPDX-FileCopyrightText: 2023 Double Open Oy <support@doubleopen.org>
 *
 * SPDX-License-Identifier: MIT
 */

package org.ossreviewtoolkit.plugins.scanners.dos

import java.time.Duration
import java.time.Instant

import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.Provenance
import org.ossreviewtoolkit.model.RepositoryProvenance
import org.ossreviewtoolkit.model.UnknownProvenance
import org.ossreviewtoolkit.model.utils.toPurl
import org.ossreviewtoolkit.model.utils.toPurlExtras

internal fun Collection<Package>.getDosPurls(provenance: Provenance = UnknownProvenance): List<String> {
    val extras = provenance.toPurlExtras()

    return when (provenance) {
        is RepositoryProvenance -> {
            map { it.id.toPurl(extras.qualifiers, it.vcsProcessed.path) }
        }

        else -> map { it.id.toPurl(extras) }
    }
}

/**
 * Elapsed time for a scanjob.
 */
internal fun elapsedTime(startTime: Instant): String {
    val currentTime = Instant.now()
    val duration = Duration.between(startTime, currentTime)
    val hours = duration.toHours()
    val minutes = duration.toMinutesPart()
    val seconds = duration.toSecondsPart()

    return "%02d:%02d:%02d".format(hours, minutes, seconds)
}