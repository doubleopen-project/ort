/*
 * Copyright (C) 2020 The ORT Project Authors (see <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>)
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

import kotlinx.coroutines.runBlocking
import org.apache.logging.log4j.kotlin.Logging
import org.ossreviewtoolkit.clients.dos.DOSRepository
import org.ossreviewtoolkit.clients.dos.DOSService
import org.ossreviewtoolkit.clients.dos.DOSService.PresignedUrlRequestBody
import org.ossreviewtoolkit.clients.dos.packZip
import org.ossreviewtoolkit.model.ScanSummary
import org.ossreviewtoolkit.model.ScannerDetails
import org.ossreviewtoolkit.model.config.DownloaderConfiguration
import org.ossreviewtoolkit.model.config.ScannerConfiguration
import org.ossreviewtoolkit.scanner.AbstractScannerWrapperFactory
import org.ossreviewtoolkit.scanner.PathScannerWrapper
import org.ossreviewtoolkit.scanner.ScanContext
import org.ossreviewtoolkit.scanner.ScannerCriteria
import java.io.File
import java.time.Instant

class DOS internal constructor(
    private val name: String,
    private val scannerConfig: ScannerConfiguration
) : PathScannerWrapper {
    private companion object : Logging

    class Factory : AbstractScannerWrapperFactory<DOS>("DOS") {
        override fun create(scannerConfig: ScannerConfiguration, downloaderConfig: DownloaderConfiguration) =
            DOS(type, scannerConfig)
    }

    override val details: ScannerDetails
        get() = ScannerDetails(name, "1.0", "")

    override val criteria: ScannerCriteria? = null

    private val service = DOSService.create()
    private val repository = DOSRepository(service)

    override fun scanPath(path: File, context: ScanContext): ScanSummary {

        val startTime = Instant.now()
        var presignedUrl: String?
        val tmpDir = "/tmp/"

        logger.info { "DOS / path to scan: $path" }

        // Zip the packet to scan
        val zipName = path.name + ".zip"
        val targetZipFile = File(tmpDir + zipName)
        path.packZip(targetZipFile)

        logger.info { "DOS / zipped scancode packet: $zipName" }

        // Request presigned URL from DOS API
        runBlocking {
            val requestBody = PresignedUrlRequestBody(zipName)
            val responseBody = service.getPresignedUrl(requestBody)
            presignedUrl = responseBody.presignedUrl

            logger.info { "DOS / presigned URL from API: $presignedUrl" }
        }

        // Transfer the zipped packet to S3 Object Storage
        runBlocking {
            presignedUrl?.let { repository.uploadFile(it, tmpDir + zipName) }
        }

        val endTime = Instant.now()

        return ScanSummary(
            startTime,
            endTime,
            emptySet(),
            emptySet(),
            emptySet(),
            emptyList()
        )
    }
}
