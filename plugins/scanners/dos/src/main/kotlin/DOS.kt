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

import java.io.File
import java.time.Instant

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

import org.apache.logging.log4j.kotlin.Logging

import org.ossreviewtoolkit.model.ScanSummary
import org.ossreviewtoolkit.model.ScannerDetails
import org.ossreviewtoolkit.model.config.DownloaderConfiguration
import org.ossreviewtoolkit.model.config.ScannerConfiguration
import org.ossreviewtoolkit.scanner.AbstractScannerWrapperFactory
import org.ossreviewtoolkit.scanner.PathScannerWrapper
import org.ossreviewtoolkit.scanner.ScanContext
import org.ossreviewtoolkit.scanner.ScannerCriteria

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
    override fun scanPath(path: File, context: ScanContext): ScanSummary {

        val startTime = Instant.now()

        logger.info { "DOS / path to scan: $path" }
        val dosUrl = System.getenv("DOS_URL")
        val spacesKey = System.getenv("SPACES_KEY")

        // Request presigned URL from DOS API
        val client = OkHttpClient()
        val endPoint = "upload-url"
        val jsonMediaType = "application/json; charset=utf-8".toMediaType()
        val jsonInputString = """{"key": "$spacesKey"}"""
        val body = jsonInputString.toRequestBody(jsonMediaType)

        val request = Request.Builder()
            .url(dosUrl + endPoint)
            .post(body)
            .build()

        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw Exception("Unexpected code $response")
            }
            // Get response body
            val presignedUrlKey = response.body?.string()
            logger.info { "DOS / presigned URL: $presignedUrlKey" }
        }

        val endTime = Instant.now()

        return ScanSummary(
            startTime,
            endTime,
            "xyz",
            emptySet(),
            emptySet(),
            emptySet(),
            emptyList()
        )
    }
}