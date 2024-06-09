/*
 * SPDX-FileCopyrightText: 2023 Double Open Oy <support@doubleopen.org>
 *
 * SPDX-License-Identifier: MIT
 */

package org.ossreviewtoolkit.plugins.scanners.dos

import java.io.File
import java.time.Instant

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking

import org.apache.logging.log4j.kotlin.logger

import org.ossreviewtoolkit.clients.dos.DOSRepository
import org.ossreviewtoolkit.clients.dos.DOSService
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
import org.ossreviewtoolkit.scanner.utils.DefaultWorkingTreeCache
import org.ossreviewtoolkit.utils.common.Options
import org.ossreviewtoolkit.utils.common.collectMessages
import org.ossreviewtoolkit.utils.common.packZip
import org.ossreviewtoolkit.utils.common.safeDeleteRecursively
import org.ossreviewtoolkit.utils.spdx.toSpdx

/**
 * DOS scanner is the ORT implementation of a ScanCode-based backend scanner, and it is a part of
 * DoubleOpen project: https://github.com/doubleopen-project/dos
 */
class DOS internal constructor(
    override val name: String,
    private val config: DOSConfig, override val readFromStorage: Boolean, override val writeToStorage: Boolean
) : PackageScannerWrapper {
    class Factory : ScannerWrapperFactory<DOSConfig>("DOS") {
        override fun create(config: DOSConfig, wrapperConfig: ScannerWrapperConfig) =
            DOS(type, config, readFromStorage = false, writeToStorage = false)

        override fun parseConfig(options: Options, secrets: Options) = DOSConfig.create(options, secrets)
    }

    override val matcher: ScannerMatcher? = null
    override val configuration = ""

    // Later on, use DOS API to return API's version and use it here
    override val version = "1.0"

    private val service = DOSService.create(config.serverUrl, config.serverToken, config.restTimeout)
    var repository = DOSRepository(service)
    private val totalScanStartTime = Instant.now()

    override fun scanPackage(nestedProvenance: NestedProvenance?, context: ScanContext): ScanResult {
        val startTime = Instant.now()

        val tmpDir = "/tmp/"
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

                    pollForCompletion(purls.first(), jobId, "Pending scan", startTime)
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

        val summary = if (scanResults?.results != null) {
            val parsedSummary = generateSummary(startTime, endTime, scanResults.results!!)
            parsedSummary.copy(issues = parsedSummary.issues + issues)
        } else {
            ScanSummary.EMPTY.copy(startTime = startTime, endTime = endTime, issues = issues)
        }

        val fixedUpLicenses = associateLicensesWithExceptions(summary.licenseFindings).mapTo(mutableSetOf()) {
            // TODO: Remove this again once fixed upstream in ORT.
            it.copy(
                license = it.license.toString().replace(
                    "GPL-2.0-only AND Classpath-exception-2.0",
                    "GPL-2.0-only WITH Classpath-exception-2.0"
                ).toSpdx()
            )
        }

        return ScanResult(
            nestedProvenance?.root ?: UnknownProvenance,
            details,
            summary.copy(licenseFindings = fixedUpLicenses)
        )
    }

    internal suspend fun runBackendScan(
        purls: List<String>,
        dosDir: File,
        tmpDir: String,
        thisScanStartTime: Instant,
        issues: MutableList<Issue>
    ): DOSService.ScanResultsResponseBody? {
        logger.info { "Initiating a backend scan" }

        // Zip the packet to scan and do local cleanup
        val zipName = dosDir.name + ".zip"
        val targetZipFile = File("$tmpDir$zipName")
        dosDir.packZip(targetZipFile)
        dosDir.safeDeleteRecursively() // ORT temp directory not needed anymore

        // Request presigned URL from DOS API
        val presignedUrl = repository.getPresignedUrl(zipName)
        if (presignedUrl == null) {
            issues += createAndLogIssue(name, "Could not get a presigned URL for this package")
            targetZipFile.delete() // local cleanup before returning
            return DOSService.ScanResultsResponseBody(DOSService.ScanResultsResponseBody.State("failed"))
        }

        // Transfer the zipped packet to S3 Object Storage and do local cleanup
        val uploadSuccessful = repository.uploadFile(presignedUrl, tmpDir + zipName)
        if (!uploadSuccessful) {
            issues += createAndLogIssue(name, "Could not upload the packet to S3")
            targetZipFile.delete() // local cleanup before returning
            return DOSService.ScanResultsResponseBody(DOSService.ScanResultsResponseBody.State("failed"))
        }
        targetZipFile.delete() // make sure the zipped packet is always deleted locally

        // Send the scan job to DOS API to start the backend scanning and do local cleanup
        val jobResponse = repository.postScanJob(zipName, purls)
        val id = jobResponse?.scannerJobId

        if (jobResponse != null) {
            logger.info { "New scan request: Packages = ${purls.joinToString()}, Zip file = $zipName" }
            if (jobResponse.message == "Adding job to queue was unsuccessful") {
                issues += createAndLogIssue(name, "DOS API: 'unsuccessful' response to the scan job request")
                return DOSService.ScanResultsResponseBody(DOSService.ScanResultsResponseBody.State("failed"))
            }
        } else {
            issues += createAndLogIssue(name, "Could not create a new scan job at DOS API")
            return DOSService.ScanResultsResponseBody(DOSService.ScanResultsResponseBody.State("failed"))
        }

        return id?.let {
            // In case of multiple PURLs, they all point to packages with the same provenance. So if one package scan is
            // complete, all package scans are complete, which is why it is enough to arbitrarily pool for the first
            // package here.
            pollForCompletion(purls.first(), it, "New scan", thisScanStartTime)
        }
    }

    private suspend fun pollForCompletion(
        purl: String,
        jobId: String,
        logMessagePrefix: String,
        thisScanStartTime: Instant
    ): DOSService.ScanResultsResponseBody? {
        while (true) {
            val jobState = repository.getJobState(jobId)
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
                        logger.error { "Scan failed" }
                        return null
                    }
                    else -> delay(config.pollInterval * 1000L)
                }
            }
        }
    }
}
