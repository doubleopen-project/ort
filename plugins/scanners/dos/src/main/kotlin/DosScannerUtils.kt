/*
 * Copyright (C) 2023 The ORT Project Authors (see <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
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
