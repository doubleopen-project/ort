/*
 * SPDX-FileCopyrightText: 2023 Double Open Oy <support@doubleopen.org>
 *
 * SPDX-License-Identifier: MIT
 */

/**
 * This file implements the needed functions to interpret the scan results from DOS API
 * to a format suited for ORT.
 */
package org.ossreviewtoolkit.plugins.scanners.dos

import java.time.Instant

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.float
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

import org.ossreviewtoolkit.model.CopyrightFinding
import org.ossreviewtoolkit.model.Issue
import org.ossreviewtoolkit.model.LicenseFinding
import org.ossreviewtoolkit.model.ScanSummary
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.model.TextLocation
import org.ossreviewtoolkit.utils.spdx.toSpdx

internal fun generateSummary(startTime: Instant, endTime: Instant, result: JsonObject): ScanSummary {
    val issues = mutableListOf<Issue>()
    val licenseFindings = result.getLicenseFindings(issues)
    val copyrightFindings = result.getCopyrightFindings()
    result.getIssues(issues)

    return ScanSummary(
        startTime,
        endTime,
        licenseFindings,
        copyrightFindings,
        emptySet(),
        issues
    )
}

private fun JsonObject.getLicenseFindings(issues: MutableList<Issue>): Set<LicenseFinding> {
    val licenses = get("licenses")?.jsonArray ?: return emptySet()

    return licenses.mapNotNullTo(mutableSetOf()) {
        val licenseNode = it.jsonObject

        val license = licenseNode.getValue("license").jsonPrimitive.content
        val location = licenseNode.getValue("location").jsonObject

        val path = location.getValue("path").jsonPrimitive.content
        val startLine = location.getValue("start_line").jsonPrimitive.int
        val endLine = location.getValue("end_line").jsonPrimitive.int
        val score = licenseNode.getValue("score").jsonPrimitive.float

        runCatching {
            license.toSpdx()
        }.map { licenseExpression ->
            LicenseFinding(licenseExpression, TextLocation(path, startLine, endLine), score)
        }.onFailure { exception ->
            issues += Issue(
                source = "DOSResultParser",
                message = "Cannot parse '$license' as an SPDX expression: ${exception.message}"
            )
        }.getOrNull()
    }
}

private fun JsonObject.getCopyrightFindings(): Set<CopyrightFinding> {
    val copyrights = get("copyrights")?.jsonArray ?: return emptySet()

    return copyrights.mapTo(mutableSetOf()) {
        val copyrightNode = it.jsonObject

        val statement = copyrightNode.getValue("statement").jsonPrimitive.content
        val location = copyrightNode.getValue("location").jsonObject

        val path = location.getValue("path").jsonPrimitive.content
        val startLine = location.getValue("start_line").jsonPrimitive.int
        val endLine = location.getValue("end_line").jsonPrimitive.int

        CopyrightFinding(statement, TextLocation(path, startLine, endLine))
    }
}

private fun JsonObject.getIssues(issues: MutableList<Issue>) {
    get("issues")?.jsonArray.orEmpty().mapTo(issues) {
        val issueNode = it.jsonObject
        val timestamp = Instant.parse(issueNode.getValue("timestamp").jsonPrimitive.content)
        val source = issueNode.getValue("source").jsonPrimitive.content
        val message = issueNode.getValue("message").jsonPrimitive.content
        val severity = Severity.valueOf(issueNode.getValue("severity").jsonPrimitive.content.uppercase())

        Issue(timestamp, source, message, severity)
    }
}
