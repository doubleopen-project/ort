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

import org.ossreviewtoolkit.utils.common.Options

/**
 * This is the configuration class for DOS Scanner.
 */
data class DOSConfig(
    /** The URL where the DOS service is running. **/
    val serverUrl: String,

    /** The secret token to use with the DOS service **/
    val serverToken: String,

    /** Interval (in seconds) to use for polling scanjob status from DOS API. **/
    val pollInterval: Int,

    /** Backend REST messaging timeout **/
    val restTimeout: Int,

    /** Use license conclusions as detected licenses when they exist? **/
    val fetchConcluded: Boolean,

    /** The URL where the DOS / package curation front-end is running. **/
    val frontendUrl: String
) {
    companion object {
        /** Name of the configuration property for the server URL. **/
        internal const val SERVER_URL_PROPERTY = "serverUrl"

        /** Secret server token needed for communicating to DOS API */
        private const val SERVER_TOKEN = "serverToken"

        /** Name of the configuration property for the polling interval. **/
        private const val POLLING_INTERVAL_PROPERTY = "pollInterval"

        /** Name of the configuration property for the REST timeout. **/
        private const val REST_TIMEOUT_PROPERTY = "restTimeout"

        /** Name of the configuration property for fetching license conclusions. **/
        private const val FETCH_CONCLUDED_PROPERTY = "fetchConcluded"

        /** Name of the configuration property for the curation front-end URL. **/
        private const val FRONT_END_URL_PROPERTY = "frontendUrl"

        private const val DEFAULT_SERVER_URL = "https://app-28ea69c2-39bc-4f55-a7e8-5cab18fedc35.cleverapps.io/api/"
        private const val DEFAULT_FRONT_END_URL = "http://localhost:3000"
        private const val DEFAULT_POLLING_INTERVAL = 5
        private const val DEFAULT_REST_TIMEOUT = 60
        private const val DEFAULT_FETCH_CONCLUDED = false

        fun create(options: Options, secrets: Options): DOSConfig {
            require(options.isNotEmpty()) { "No DOS Scanner configuration found." }

            val serverUrl = options[SERVER_URL_PROPERTY] ?: DEFAULT_SERVER_URL

            val serverToken = requireNotNull(secrets[SERVER_TOKEN]) {
                "Server token not set!"
            }

            val pollInterval = options[POLLING_INTERVAL_PROPERTY]?.toInt() ?: DEFAULT_POLLING_INTERVAL

            require(pollInterval >= DEFAULT_POLLING_INTERVAL) {
                "Polling interval must be >= $DEFAULT_POLLING_INTERVAL, current value is $pollInterval"
            }

            val restTimeout = options[REST_TIMEOUT_PROPERTY]?.toInt() ?: DEFAULT_REST_TIMEOUT

            require(restTimeout >= DEFAULT_REST_TIMEOUT) {
                "REST timeout must be >= $DEFAULT_REST_TIMEOUT, current value is $restTimeout"
            }

            val fetchConcluded = options[FETCH_CONCLUDED_PROPERTY]?.toBoolean() ?: DEFAULT_FETCH_CONCLUDED

            val frontendUrl = options[FRONT_END_URL_PROPERTY] ?: DEFAULT_FRONT_END_URL

            return DOSConfig(
                serverUrl = serverUrl,
                serverToken = serverToken,
                pollInterval = pollInterval,
                restTimeout = restTimeout,
                fetchConcluded = fetchConcluded,
                frontendUrl = frontendUrl
            )
        }
    }
}
