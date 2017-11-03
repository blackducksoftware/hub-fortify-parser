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

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.univocity.parsers.annotations.Parsed;

/**
 * Bean mapped to output of the Hub CSV report
 * If the columns change, the mappings here will need to be updated.
 *
 * @author akamen
 *
 */
public class BlackDuckIssue {
    private static Logger LOG = LoggerFactory.getLogger(BlackDuckIssue.class);

    /**
     * Unique natural issue identifier.
     */
    private String issueId;

    @Parsed(field = "Project name")
    private String projectName;

    @Parsed(field = "Project version")
    private String projectVersion;

    @Parsed(field = "Component name")
    private String componentName;

    @Parsed(field = "Component Version")
    private String componentVersion;

    @Parsed(field = "Component id")
    private String componentId;

    @Parsed(field = "Component Version id")
    private String componentVersionId;

    @Parsed(field = "Released On")
    private String releasedOn;

    @Parsed(field = "Newer Released Count")
    private String newerReleasedCount;

    @Parsed(field = "Trending")
    private String trending;

    @Parsed(field = "Commit Count Last 12 Month")
    private String commitCount12Month;

    @Parsed(field = "Contributor Count Last 12 Month")
    private String contributorCount12Month;

    @Parsed(field = "URL")
    private String URL;

    @Parsed(field = "Severity")
    private String severity;

    @Parsed(field = "Scan date")
    private String scanDate;

    /**
     * Returns the unique ID of this particular issue.
     * Using an internal id plus the supplied name via the setId()
     * Format will be supplied name during setid + ":" + vulnerability ID
     *
     * @return unique issue ID
     */
    public String getId() {
        if (issueId == null) {
            String uuidData = String.format("%s:%s:%s:%s", BlackDuckUtils.cleanName(componentId), BlackDuckUtils.cleanName(componentVersionId));
            issueId = UUID.nameUUIDFromBytes(uuidData.getBytes()).toString();
            LOG.debug("Component Id~" + BlackDuckUtils.cleanName(componentId) + ", Version Id~" + BlackDuckUtils.cleanName(componentVersionId)
                    + ", issueId~" + issueId);
        }
        return issueId;
    }

    public String getIssueId() {
        return issueId;
    }

    public void setIssueId(String issueId) {
        this.issueId = issueId;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getProjectVersion() {
        return projectVersion;
    }

    public void setProjectVersion(String projectVersion) {
        this.projectVersion = projectVersion;
    }

    public String getComponentName() {
        return componentName;
    }

    public void setComponentName(String componentName) {
        this.componentName = componentName;
    }

    public String getComponentVersion() {
        return componentVersion;
    }

    public void setComponentVersion(String componentVersion) {
        this.componentVersion = componentVersion;
    }

    public String getComponentId() {
        return componentId;
    }

    public void setComponentId(String componentId) {
        this.componentId = componentId;
    }

    public String getComponentVersionId() {
        return componentVersionId;
    }

    public void setComponentVersionId(String componentVersionId) {
        this.componentVersionId = componentVersionId;
    }

    public String getReleasedOn() {
        return releasedOn;
    }

    public void setReleasedOn(String releasedOn) {
        this.releasedOn = releasedOn;
    }

    public String getNewerReleasedCount() {
        return newerReleasedCount;
    }

    public void setNewerReleasedCount(String newerReleasedCount) {
        this.newerReleasedCount = newerReleasedCount;
    }

    public String getTrending() {
        return trending;
    }

    public void setTrending(String trending) {
        this.trending = trending;
    }

    public String getCommitCount12Month() {
        return commitCount12Month;
    }

    public void setCommitCount12Month(String commitCount12Month) {
        this.commitCount12Month = commitCount12Month;
    }

    public String getContributorCount12Month() {
        return contributorCount12Month;
    }

    public void setContributorCount12Month(String contributorCount12Month) {
        this.contributorCount12Month = contributorCount12Month;
    }

    public String getURL() {
        return URL;
    }

    public void setURL(String uRL) {
        URL = uRL;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getScanDate() {
        return scanDate;
    }

    public void setScanDate(String scanDate) {
        this.scanDate = scanDate;
    }

}
