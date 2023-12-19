package org.ossreviewtoolkit.clients.dos

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.ossreviewtoolkit.clients.dos.DOSService.Companion.logger
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths

class DOSRepository(private val dosService: DOSService) {
    /**
     * Upload a file to S3, using presigned URL, and if successful,
     * delete the file from local storage.
     */
    suspend fun uploadFile(presignedUrl: String, filePath: String): Boolean {
        val file = File(filePath)
        val requestBody = file.readBytes().toRequestBody("application/zip".toMediaType())
        val response = dosService.putS3File(presignedUrl, requestBody)

        if (!response.isSuccessful) {
            logger.error { "Failed to upload packet to S3: ${response.message()}" }
            return false
        } else {
            logger.info { "Packet successfully uploaded to S3!" }
            return true
        }
    }
}
