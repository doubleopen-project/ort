/*
 * SPDX-FileCopyrightText: 2023 HH Partners
 *
 * SPDX-License-Identifier: MIT
 */

package org.ossreviewtoolkit.clients.dos

import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory

import kotlinx.serialization.json.Json
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

import okhttp3.logging.HttpLoggingInterceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.RequestBody

import org.apache.logging.log4j.kotlin.Logging

import retrofit2.http.*
import retrofit2.Response
import retrofit2.Retrofit

/**
 * A Retrofit2 interface to define the network layer of the DOS client.
 */
interface DOSService {

    companion object: Logging {
        /**
         * The JSON (de-)serialization object used by this service.
         */
        private val JSON = Json {
            ignoreUnknownKeys = true
        }

        /**
         * Create a new service instance that connects to the [url] specified and uses the optionally provided [client].
         */
        fun create(url: String, client: OkHttpClient? = null): DOSService {
            val contentType = "application/json; charset=utf-8".toMediaType()

            val loggingInterceptor = HttpLoggingInterceptor().apply {
                // For logging basic call-response statuses, use BASIC
                // For logging the request and response bodies of a call, use BODY
                level = HttpLoggingInterceptor.Level.NONE
            }

            val okHttpClient = client ?: OkHttpClient.Builder()
                .addInterceptor(loggingInterceptor)
                .build()

            val retrofit = Retrofit.Builder()
                .client(okHttpClient)
                .baseUrl(url)
                .addConverterFactory(JSON.asConverterFactory(contentType))
                .build()

            return retrofit.create(DOSService::class.java)
        }
    }

    @Serializable
    data class UploadUrlRequestBody(
        val key: String? = null
    )

    @Serializable
    data class UploadUrlResponseBody(
        val success: Boolean,
        val presignedUrl: String? = null,
        val message: String? = null
    )

    @Serializable
    data class ScanResultsRequestBody(
        val purl: String? = null
    )

    @Serializable
    data class ScanResultsResponseBody(
        val state: State,
        val results: JsonElement? = null
    ) {
        @Serializable
        data class State(
            val status: String,
            val id: String? = null
        )
    }

    @Serializable
    data class PackageRequestBody(
        val zipFileKey: String? = null,
        val purl: String? = null
    )

    @Serializable
    data class PackageResponseBody(
        val folderName: String? = null,
        val packageId: Int = 0
    )

    @Serializable
    data class JobRequestBody(
        val directory: String? = null,
        val packageId: Int = 0
    )

    @Serializable
    data class JobResponseBody(
        val scannerJob: ScannerJob,
        val message: String?
    ) {
        @Serializable
        data class ScannerJob(
            val id: String,
            val createdAt: String? = null,
            val packageId: Int = 0
        )
    }

    @Serializable
    data class JobStateResponseBody(
        val state: String? = null
    )

    @PUT
    suspend fun putS3File(@Url url: String, @Body file: RequestBody): Response<Unit>

    @POST("upload-url")
    suspend fun postUploadUrl(@Body body: UploadUrlRequestBody): Response<UploadUrlResponseBody>

    @POST("scan-results")
    suspend fun postScanResults(@Body body: ScanResultsRequestBody): Response<ScanResultsResponseBody>

    @POST("package")
    suspend fun postPackage(@Body body: PackageRequestBody): Response<PackageResponseBody>

    @POST("job")
    suspend fun postJob(@Body body: JobRequestBody): Response<JobResponseBody>

    @GET("job-state/{id}")
    suspend fun getJobState(@Path("id") id: String): Response<JobStateResponseBody>
}
