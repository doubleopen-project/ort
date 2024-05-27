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
import org.ossreviewtoolkit.clients.dos.deleteFileOrDir
import org.ossreviewtoolkit.clients.dos.packZip
import org.ossreviewtoolkit.model.*
import org.ossreviewtoolkit.model.config.DownloaderConfiguration
import org.ossreviewtoolkit.model.config.ScannerConfiguration
import org.ossreviewtoolkit.scanner.*
import org.ossreviewtoolkit.downloader.Downloader
import org.ossreviewtoolkit.utils.ort.createOrtTempDir
import org.ossreviewtoolkit.scanner.storages.utils.ScanResults
import java.io.File
import java.time.Instant

/**
 * DOS scanner is the ORT implementation of a ScanCode-based backend scanner, and it is a part of
 * DoubleOpen project: https://github.com/doubleopen-project/dos
 *
 * Copyright (c) 2023 HH Partners
 */
class DOS internal constructor(
    override val name: String,
    private val scannerConfig: ScannerConfiguration,
    override val version: String,
    override val configuration: String
) : PackageScannerWrapper {
    private companion object : Logging
    private val downloaderConfig = DownloaderConfiguration()

    class Factory : AbstractScannerWrapperFactory<DOS>("DOS") {
        override fun create(scannerConfig: ScannerConfiguration, downloaderConfig: DownloaderConfiguration) =
            DOS(type, scannerConfig, "1.0", "")
    }

    override val details: ScannerDetails
        get() = ScannerDetails(name, "1.0", "")

    override val criteria: ScannerCriteria? = null

    private val service = DOSService.create()
    private val repository = DOSRepository(service)

    override fun scanPackage(pkg: Package, context: ScanContext): ScanResult {

        val startTime = Instant.now()
        val tmpDir = "/tmp/"
        val provenance: Provenance

        logger.info { "Package to scan: $pkg" }
        // Use ORT specific local file structure
        val dosDir = createOrtTempDir()

        runBlocking {
            // Download the package
            val downloader = Downloader(downloaderConfig)
            provenance = downloader.download(pkg, dosDir)
            logger.info { "Package downloaded to: $dosDir" }

            // Ask for scan results from DOS/API
            // 1st (trivial) case: null returned, indicating no earlier scan results for this PURL
            logger.info { "Package URL: ${pkg.purl}" }
            val scanResults = repository.getScanResults(pkg.purl)
            logger.info { "Earlier scan results for this package: $scanResults" }

            // Zip the packet to scan
            val zipName = dosDir.name + ".zip"
            val targetZipFile = File("$tmpDir$zipName")
            dosDir.packZip(targetZipFile)
            logger.info { "Zipped packet: $zipName" }

            // Request presigned URL from DOS API
            val presignedUrl = repository.getPresignedUrl(zipName)
            logger.info { "Presigned URL from API: $presignedUrl" }

            // Transfer the zipped packet to S3 Object Storage
            presignedUrl?.let {
                val uploadSuccessful = repository.uploadFile(it, tmpDir + zipName)

                // If upload to S3 was successful, do local cleanup
                if (uploadSuccessful) {
                    deleteFileOrDir(dosDir)
                    //deleteFileOrDir(targetZipFile) // don't do this here
                }
            }

            // Notify DOS API about the new zipped file at S3, and get the unzipped folder
            // name as a return
            logger.info { "Zipped file at S3: $zipName" }
            val scanFolder = repository.getScanFolder(zipName)
            logger.info { "S3 folder to scan: $scanFolder" }

            // Send the scan job to DOS API to start the backend scanning

        }



        // Get the results back as a JSON string

        val endTime = Instant.now()

        // Convert results to ORT form

        val summary = ScanSummary(
            startTime,
            endTime,
            emptySet(),
            emptySet(),
            emptySet(),
            emptyList()
        )

        return ScanResult(
            provenance,
            details,
            summary
        )
    }
}
