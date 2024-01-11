/*
 * SPDX-FileCopyrightText: 2023 HH Partners
 *
 * SPDX-License-Identifier: MIT
 */

package org.ossreviewtoolkit.plugins.scanners.dos

import java.io.File
import java.time.Instant

import kotlinx.coroutines.delay
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

/**
 * DOS scanner is the ORT implementation of a ScanCode-based backend scanner, and it is a part of
 * DoubleOpen project: https://github.com/doubleopen-project/dos
 *
 * Copyright (c) 2023 HH Partners
 */
class DOS internal constructor(
    override val name: String,
    private val scannerConfig: ScannerConfiguration,
    private val config: DOSConfig
) : PackageScannerWrapper {
    private companion object : Logging
    private val downloaderConfig = DownloaderConfiguration()

    class Factory : AbstractScannerWrapperFactory<DOS>("DOS") {
        override fun create(scannerConfig: ScannerConfiguration, downloaderConfig: DownloaderConfiguration) =
            DOS(type, scannerConfig, DOSConfig.create(scannerConfig))
    }

    override val details: ScannerDetails
        get() = ScannerDetails(name, version, configuration)
    override val criteria: ScannerCriteria? = null
    override val configuration = ""
    override val version = "1.0"

    private val service = DOSService.create(config.serverUrl)
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
            val results = repository.getScanResults(pkg.purl)

            if (results == null) {
                // Zip the packet to scan
                val zipName = dosDir.name + ".zip"
                val targetZipFile = File("$tmpDir$zipName")
                dosDir.packZip(targetZipFile)

                // Request presigned URL from DOS API
                val presignedUrl = repository.getPresignedUrl(zipName)

                // Transfer the zipped packet to S3 Object Storage
                presignedUrl?.let {
                    val uploadSuccessful = repository.uploadFile(it, tmpDir + zipName)

                    // If upload to S3 was successful, do local cleanup
                    if (uploadSuccessful) {
                        deleteFileOrDir(dosDir)
                    }
                }

                // Notify DOS API about the new zipped file at S3, and get the unzipped folder
                // name as a return
                logger.info { "Zipped file at S3: $zipName" }
                val scanFolder = repository.getScanFolder(zipName)
                deleteFileOrDir(targetZipFile)

                // Send the scan job to DOS API to start the backend scanning
                val response = scanFolder?.let { repository.postScanJob(it) }
                val id = response?.scannerJob?.id
                if (response != null) {
                    logger.info { "Response to scan request: id = $id, message = ${response.message}" }
                }

                // Poll the job state periodically and log
                var jobState = ""
                while (jobState != "completed") {
                    jobState = id?.let { repository.getJobState(it) }.toString()
                    logger.info { "Job state: id = $id, state = $jobState" }
                    if (jobState != "completed") {
                        delay(config.pollInterval * 1000L)
                    }
                }
            }
        }

        // Get the results back as a JSON string

        val endTime = Instant.now()

        // Convert results to ORT form

        val summary = generateSummary(
            startTime,
            endTime,
            "{\n" +
                    "    \"results\": {\n" +
                    "        \"licenses\": [\n" +
                    "            {\n" +
                    "                \"license\": \"license\",\n" +
                    "                \"location\": {\n" +
                    "                    \"path\": \"path/to/file\",\n" +
                    "                    \"start_line\": 1,\n" +
                    "                    \"end_line\": 1\n" +
                    "                },\n" +
                    "                \"score\": 100.0\n" +
                    "            }\n" +
                    "        ],\n" +
                    "        \"copyrights\": [\n" +
                    "            {\n" +
                    "                \"statement\": \"statement\",\n" +
                    "                \"location\": {\n" +
                    "                    \"path\": \"path/to/file\",\n" +
                    "                    \"start_line\": 1,\n" +
                    "                    \"end_line\": 1\n" +
                    "                }\n" +
                    "            }\n" +
                    "        ]\n" +
                    "    } \n" +
                    "}"
        )

        return ScanResult(
            provenance,
            details,
            summary
        )
    }
}
