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

import java.io.File
import java.time.Duration
import java.time.Instant

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking

import org.apache.logging.log4j.kotlin.logger

import org.ossreviewtoolkit.clients.dos.DosClient
import org.ossreviewtoolkit.clients.dos.DosService
import org.ossreviewtoolkit.clients.dos.ScanResultsResponseBody
import org.ossreviewtoolkit.downloader.DefaultWorkingTreeCache
import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.ScanResult
import org.ossreviewtoolkit.model.ScanSummary
import org.ossreviewtoolkit.model.UnknownProvenance
import org.ossreviewtoolkit.model.config.DownloaderConfiguration
import org.ossreviewtoolkit.model.createAndLogIssue
import org.ossreviewtoolkit.model.utils.associateLicensesWithExceptions
import org.ossreviewtoolkit.scanner.PackageScannerWrapper
import org.ossreviewtoolkit.scanner.ScanContext
import org.ossreviewtoolkit.scanner.ScannerMatcher
import org.ossreviewtoolkit.scanner.ScannerWrapperConfig
import org.ossreviewtoolkit.scanner.ScannerWrapperFactory
import org.ossreviewtoolkit.scanner.provenance.DefaultProvenanceDownloader
import org.ossreviewtoolkit.scanner.provenance.NestedProvenance
import org.ossreviewtoolkit.utils.common.Options
import org.ossreviewtoolkit.utils.common.collectMessages
import org.ossreviewtoolkit.utils.common.packZip
import org.ossreviewtoolkit.utils.common.safeDeleteRecursively
import org.ossreviewtoolkit.utils.ort.createOrtTempDir

/**
 * DOS scanner is the ORT implementation of a ScanCode-based backend scanner, and it is a part of
 * DoubleOpen project: https://github.com/doubleopen-project/dos
 */
class DosScanner internal constructor(
    override val name: String,
    private val config: DosScannerConfig, override val readFromStorage: Boolean, override val writeToStorage: Boolean
) : PackageScannerWrapper {
    class Factory : ScannerWrapperFactory<DosScannerConfig>("DOS") {
        override fun create(config: DosScannerConfig, wrapperConfig: ScannerWrapperConfig) =
            DosScanner(type, config, readFromStorage = false, writeToStorage = false)

        override fun parseConfig(options: Options, secrets: Options) = DosScannerConfig.create(options, secrets)
    }

    override val matcher: ScannerMatcher? = null
    override val configuration = ""

    // Later on, use DOS API to return API's version and use it here
    override val version = "1.0"

    private val service = DosService.create(config.url, config.token, config.timeout?.let { Duration.ofSeconds(it) })
    var repository = DosClient(service)
    private val totalScanStartTime = Instant.now()

    override fun scanPackage(nestedProvenance: NestedProvenance?, context: ScanContext): ScanResult {
        val startTime = Instant.now()

        // TODO: Delete this again.
        val tmpDir = createOrtTempDir()
        val issues = mutableListOf<Issue>()

        val scanResults = runBlocking {
            val provenance = nestedProvenance?.root ?: run {
                logger.warn {
                    val cleanPurls = context.coveredPackages.joinToString { it.purl }
                    "Skipping scan as no provenance information is available for these packages: $cleanPurls"
                }

                return@runBlocking null
            }

            val purls = context.coveredPackages.getDosPurls(provenance)

            logger.info { "Packages requested for scanning: ${purls.joinToString()}" }

            // Ask for scan results from DOS API
            val existingScanResults = runCatching {
                repository.getScanResults(purls, config.fetchConcluded)
            }.onFailure {
                issues += createAndLogIssue(name, it.collectMessages())
            }.onSuccess {
                if (it == null) issues += createAndLogIssue(name, "Could not request scan results from DOS API")
            }.getOrNull()

            when (existingScanResults?.state?.status) {
                "no-results" -> {
                    val downloader = DefaultProvenanceDownloader(DownloaderConfiguration(), DefaultWorkingTreeCache())

                    runCatching {
                        downloader.download(provenance)
                    }.mapCatching { dosDir ->
                        logger.info { "Package downloaded to: $dosDir" }
                        runBackendScan(purls, dosDir, tmpDir, startTime, issues)
                    }.onFailure {
                        issues += createAndLogIssue(name, it.collectMessages())
                    }.getOrNull()
                }

                "pending" -> {
                    val jobId = checkNotNull(existingScanResults.state.jobId) {
                        "The job ID must not be null for 'pending' status."
                    }

                    pollForCompletion(purls.first(), jobId, "Pending scan", startTime, issues)
                }

                "ready" -> existingScanResults

                "failed" -> {
                    issues += createAndLogIssue(
                        name,
                        "Something went wrong at DOS backend, exiting scan of this package"
                    )

                    null
                }

                else -> null
            }
        }

        val endTime = Instant.now()

        val scanResultsJson = scanResults?.results
        val summary = if (scanResultsJson != null) {
            val parsedSummary = generateSummary(startTime, endTime, scanResultsJson)
            parsedSummary.copy(issues = parsedSummary.issues + issues)
        } else {
            ScanSummary.EMPTY.copy(startTime = startTime, endTime = endTime, issues = issues)
        }

        return ScanResult(
            nestedProvenance?.root ?: UnknownProvenance,
            details,
            summary.copy(licenseFindings = associateLicensesWithExceptions(summary.licenseFindings))
        )
    }

    internal suspend fun runBackendScan(
        purls: List<String>,
        dosDir: File,
        tmpDir: File,
        thisScanStartTime: Instant,
        issues: MutableList<Issue>
    ): ScanResultsResponseBody? {
        logger.info { "Initiating a backend scan" }

        // Zip the packet to scan and do local cleanup
        val zipName = dosDir.name + ".zip"
        val targetZipFile = tmpDir.resolve(zipName)
        dosDir.packZip(targetZipFile)
        dosDir.safeDeleteRecursively() // ORT temp directory not needed anymore

        // Request presigned URL from DOS API
        val presignedUrl = repository.getUploadUrl(zipName)
        if (presignedUrl == null) {
            issues += createAndLogIssue(name, "Could not get a presigned URL for this package")
            targetZipFile.delete() // local cleanup before returning
            return ScanResultsResponseBody(ScanResultsResponseBody.State("failed"))
        }

        // Transfer the zipped packet to S3 Object Storage and do local cleanup
        val uploadSuccessful = repository.uploadFile(targetZipFile, presignedUrl)
        if (!uploadSuccessful) {
            issues += createAndLogIssue(name, "Could not upload the packet to S3")
            targetZipFile.delete() // local cleanup before returning
            return ScanResultsResponseBody(ScanResultsResponseBody.State("failed"))
        }
        targetZipFile.delete() // make sure the zipped packet is always deleted locally

        // Send the scan job to DOS API to start the backend scanning and do local cleanup
        val jobResponse = repository.addScanJob(zipName, purls)
        val id = jobResponse?.scannerJobId

        if (jobResponse != null) {
            logger.info { "New scan request: Packages = ${purls.joinToString()}, Zip file = $zipName" }
            if (jobResponse.message == "Adding job to queue was unsuccessful") {
                issues += createAndLogIssue(name, "DOS API: 'unsuccessful' response to the scan job request")
                return ScanResultsResponseBody(ScanResultsResponseBody.State("failed"))
            }
        } else {
            issues += createAndLogIssue(name, "Could not create a new scan job at DOS API")
            return ScanResultsResponseBody(ScanResultsResponseBody.State("failed"))
        }

        return id?.let {
            // In case of multiple PURLs, they all point to packages with the same provenance. So if one package scan is
            // complete, all package scans are complete, which is why it is enough to arbitrarily pool for the first
            // package here.
            pollForCompletion(purls.first(), it, "New scan", thisScanStartTime, issues)
        }
    }

    private suspend fun pollForCompletion(
        purl: String,
        jobId: String,
        logMessagePrefix: String,
        thisScanStartTime: Instant,
        issues: MutableList<Issue>
    ): ScanResultsResponseBody? {
        while (true) {
            val jobState = repository.getScanJobState(jobId)
            if (jobState != null) {
                logger.info {
                    "$logMessagePrefix: ${elapsedTime(thisScanStartTime)}/${elapsedTime(totalScanStartTime)}, " +
                        "state = ${jobState.state.status}, " +
                        "message = ${jobState.state.message}"
                }
            }
            if (jobState != null) {
                when (jobState.state.status) {
                    "completed" -> {
                        logger.info { "Scan completed" }
                        return repository.getScanResults(listOf(purl), config.fetchConcluded)
                    }
                    "failed" -> {
                        issues += createAndLogIssue(name, "Scan failed in DOS API")
                        return null
                    }
                    else -> delay(config.pollInterval * 1000L)
                }
            }
        }
    }
}
