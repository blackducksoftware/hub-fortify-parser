package com.blackducksoftware.integration.fortify;

import com.univocity.parsers.annotations.Parsed;

/**
 * Bean mapped to output of the Hub CSV report
 * If the columns change, the mappings here will need to be updated.
 * 
 * @author akamen
 * 
 */
public class BlackDuckIssue {

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
    private float baseScore;

    @Parsed(field = "Exploitability")
    private float exploitability;

    @Parsed(field = "Impact")
    private float impact;

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

    private String issueId;

    public void setId(String name) {
        issueId = cleanName(name) + ":" + vulnerabilityId;
    }

    /**
     * * Returns the unique ID of this particular issue.
     * Using an internal id plus the supplied name via the setId()
     * 
     * Format will be supplied name during setid + ":" + vulnerability ID
     * 
     * @return
     */
    public String getId()
    {
        if (issueId == null) {
            setId("");
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

    public float getBaseScore() {
        return baseScore;
    }

    public void setBaseScore(float baseScore) {
        this.baseScore = baseScore;
    }

    public float getExploitability() {
        return exploitability;
    }

    public void setExploitability(float exploitability) {
        this.exploitability = exploitability;
    }

    public float getImpact() {
        return impact;
    }

    public void setImpact(float impact) {
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

    /**
     * @param name2
     * @return
     */
    private String cleanName(String name) {
        name = name.replace(" ", "");
        return name;
    }

}
