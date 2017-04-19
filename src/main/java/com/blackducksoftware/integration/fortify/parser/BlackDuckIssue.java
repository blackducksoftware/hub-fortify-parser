/**
 * Copyright (C) 2016 Black Duck Software, Inc.
 * http://www.blackducksoftware.com/
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.
 *
 * The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.blackducksoftware.integration.fortify.parser;

import com.univocity.parsers.annotations.Parsed;

import java.math.BigDecimal;
import java.util.UUID;

/**
 * Bean mapped to output of the Hub CSV report
 * If the columns change, the mappings here will need to be updated.
 *
 * @author akamen
 *
 */
public class BlackDuckIssue {

    /**
     * Unique natural issue identifier.
     */
    private String issueId;

    @Parsed(field = "Project id")
    private String projectId;

    @Parsed(field = "Version id")
    private String versionId;

    @Parsed(field = "Channel version id")
    private String channelVersionId;

    @Parsed(field = "Project name")
    private String projectName;

    @Parsed(field = "Version")
    private String version;

    @Parsed(field = "Channel version origin")
    private String channelVersionOrigin;

    @Parsed(field = "Channel version origin id")
    private String channelVersionOriginId;

    @Parsed(field = "Channel version origin name")
    private String channelVersionOriginName;

    @Parsed(field = "Vulnerability id")
    private String vulnerabilityId;

    @Parsed(field = "Description")
    private String description;

    @Parsed(field = "Published on")
    private String publishedOn;

    @Parsed(field = "Updated on")
    private String updatedOn;

    @Parsed(field = "Base Score")
    private BigDecimal baseScore;

    @Parsed(field = "Exploitability")
    private BigDecimal exploitability;

    @Parsed(field = "Impact")
    private BigDecimal impact;

    @Parsed(field = "Vulnerability source")
    private String vulnerabilitySource;

    @Parsed(field = "Remediation status")
    private String remediationStatus;

    @Parsed(field = "Remediation target date")
    private String remediationTargetDate;

    @Parsed(field = "Remediation actual date")
    private String remediationActualDate;

    @Parsed(field = "Remediation comment")
    private String remediationComment;

    @Parsed(field = "URL")
    private String URL;

    /**
     * Returns the unique ID of this particular issue.
     * Using an internal id plus the supplied name via the setId()
     * Format will be supplied name during setid + ":" + vulnerability ID
     *
     * @return unique issue ID
     */
    public String getId() {
        if (issueId == null) {
            String uuidData = String.format("%s:%s", BlackDuckUtils.cleanName(projectName), vulnerabilityId);
            issueId = UUID.nameUUIDFromBytes(uuidData.getBytes()).toString();
        }
        return issueId;
    }

    public String getProjectId() {
        return projectId;
    }

    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }

    public String getVersionId() {
        return versionId;
    }

    public void setVersionId(String versionId) {
        this.versionId = versionId;
    }

    public String getChannelVersionId() {
        return channelVersionId;
    }

    public void setChannelVersionId(String channelVersionId) {
        this.channelVersionId = channelVersionId;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getChannelVersionOrigin() {
        return channelVersionOrigin;
    }

    public void setChannelVersionOrigin(String channelVersionOrigin) {
        this.channelVersionOrigin = channelVersionOrigin;
    }

    public String getChannelVersionOriginId() {
        return channelVersionOriginId;
    }

    public void setChannelVersionOriginId(String channelVersionOriginId) {
        this.channelVersionOriginId = channelVersionOriginId;
    }

    public String getChannelVersionOriginName() {
        return channelVersionOriginName;
    }

    public void setChannelVersionOriginName(String channelVersionOriginName) {
        this.channelVersionOriginName = channelVersionOriginName;
    }

    public String getVulnerabilityId() {
        return vulnerabilityId;
    }

    public void setVulnerabilityId(String vulnerabilityId) {
        this.vulnerabilityId = vulnerabilityId;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getPublishedOn() {
        return publishedOn;
    }

    public void setPublishedOn(String publishedOn) {
        this.publishedOn = publishedOn;
    }

    public String getUpdatedOn() {
        return updatedOn;
    }

    public void setUpdatedOn(String updatedOn) {
        this.updatedOn = updatedOn;
    }

    public BigDecimal getBaseScore() {
        return baseScore;
    }

    public void setBaseScore(BigDecimal baseScore) {
        this.baseScore = baseScore;
    }

    public BigDecimal getExploitability() {
        return exploitability;
    }

    public void setExploitability(BigDecimal exploitability) {
        this.exploitability = exploitability;
    }

    public BigDecimal getImpact() {
        return impact;
    }

    public void setImpact(BigDecimal impact) {
        this.impact = impact;
    }

    public String getVulnerabilitySource() {
        return vulnerabilitySource;
    }

    public void setVulnerabilitySource(String vulnerabilitySource) {
        this.vulnerabilitySource = vulnerabilitySource;
    }

    public String getRemediationStatus() {
        return remediationStatus;
    }

    public void setRemediationStatus(String remediationStatus) {
        this.remediationStatus = remediationStatus;
    }

    public String getRemediationTargetDate() {
        return remediationTargetDate;
    }

    public void setRemediationTargetDate(String remediationTargetDate) {
        this.remediationTargetDate = remediationTargetDate;
    }

    public String getRemediationActualDate() {
        return remediationActualDate;
    }

    public void setRemediationActualDate(String remediationActualDate) {
        this.remediationActualDate = remediationActualDate;
    }

    public String getRemediationComment() {
        return remediationComment;
    }

    public void setRemediationComment(String remediationComment) {
        this.remediationComment = remediationComment;
    }

    public String getURL() {
        return URL;
    }

    public void setURL(String URL) {
        this.URL = URL;
    }
}
